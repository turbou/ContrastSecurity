#!/bin/bash

if [ -z "$CONTRAST_BASEURL" -o -z "$CONTRAST_API_KEY" -o -z "$CONTRAST_USERNAME" -o -z "$CONTRAST_SERVICE_KEY" ]; then
    echo '環境変数が設定されていません。'
    echo 'CONTRAST_BASEURL       : https://(app|eval).contrastsecurity.com/Contrast'
    echo 'CONTRAST_API_KEY       : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    echo 'CONTRAST_USERNAME      : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    echo 'CONTRAST_SERVICE_KEY   : XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
    echo '!!注意!! USERNAME, SERVICE_KEYはSuperAdmin権限を持つユーザーとしてください。'
    exit 1
fi

BASEURL=$CONTRAST_BASEURL
API_KEY=$CONTRAST_API_KEY
USERNAME=$CONTRAST_USERNAME       # SuperAdminユーザー
SERVICE_KEY=$CONTRAST_SERVICE_KEY # SuperAdminユーザー
AUTHORIZATION=`echo "$(echo -n $USERNAME:$SERVICE_KEY | base64)"`
API_URL="${BASEURL}/api/ng"
GROUP_NAME=RulesAdminGroup

# 既存のグループを取得します。
rm -f ./groups.json
curl -X GET -sS -G \
     ${API_URL}/superadmin/ac/groups \
     -d expand=scopes,skip_links -d q=${GROUP_NAME} -d quickFilter=CUSTOM \
     -H "Authorization: ${AUTHORIZATION}" \
     -H "API-Key: ${API_KEY}" \
     -H 'Accept: application/json' -J -o groups.json

GRP_ID=`cat ./groups.json | jq -r --arg grp_name "${GROUP_NAME}" '.groups[] | select(.name==$grp_name) | .group_id'`

# 組織一覧を取得します。
rm -f ./organizaions.json
curl -X GET -sS -G \
     ${API_URL}/superadmin/organizations \
     -d base=base -d expand=skip_links \
     -H "Authorization: ${AUTHORIZATION}" \
     -H "API-Key: ${API_KEY}" \
     -H 'Accept: application/json' -J -o organizations.json

# 組織IDからjson配列を生成します。
SCOPES=
while read -r ORG_ID; do
    SCOPES=$SCOPES'{"org":{"id":"'$ORG_ID'","role":"rules_admin"},"app":{"exceptions":[]}},'
done < <(cat ./organizations.json | jq -r '.organizations[].organization_uuid')
SCOPES=`echo $SCOPES | sed "s/,$//"`
SCOPES="["$SCOPES"]"

# グループがない場合は作成、ある場合は組織の割当を更新します。
if [ "${GRP_ID}" = "" ]; then
    curl -X POST -sS \
        ${API_URL}/superadmin/ac/groups/organizational?expand=skip_links \
        -H "Authorization: ${AUTHORIZATION}" \
        -H "API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -H 'Accept: application/json' \
        -d '{"name":"'$GROUP_NAME'","users":["'$USERNAME'"],"scopes":'$SCOPES'}'
else
    curl -X PUT -sS \
        ${API_URL}/superadmin/ac/groups/organizational/${GRP_ID}?expand=skip_links \
        -H "Authorization: ${AUTHORIZATION}" \
        -H "API-Key: ${API_KEY}" \
        -H "Content-Type: application/json" \
        -H 'Accept: application/json' \
        -d '{"name":"'$GROUP_NAME'","users":["'$USERNAME'"],"scopes":'$SCOPES'}'
fi

# 組織ごとのAPIキーを取得します。
rm -f orgid_apikey_map.txt
while read -r ORG_ID; do
    curl -X GET -sS -G \
         ${API_URL}/superadmin/users/${ORG_ID}/keys/apikey?expand=skip_links \
         -d base=base -d expand=skip_links \
         -H "Authorization: ${AUTHORIZATION}" \
         -H "API-Key: ${API_KEY}" \
         -H 'Accept: application/json' -J -o apikey.json
    GET_API_KEY=`cat ./apikey.json | jq -r '.api_key'`
    echo "$ORG_ID:$GET_API_KEY" >> orgid_apikey_map.txt
done < <(cat ./organizations.json | jq -r '.organizations[].organization_uuid')

# 組織ごとにルールの重大度を反映していきます。
while read -r ORG_ID; do
    ORG_API_KEY=`grep ${ORG_ID} ./orgid_apikey_map.txt | awk -F: '{print $2}'`
    while read -r RULE_NAME; do
        echo ""
        echo "${RULE_NAME}"
        IMPACT=`cat ./rules.json | jq -r --arg title "$RULE_NAME" '.rules[] | select(.name==$title) | .impact'`
        LIKELIHOOD=`cat ./rules.json | jq -r --arg title "$RULE_NAME" '.rules[] | select(.name==$title) | .likelihood'`
        CONFIDENCE=`cat ./rules.json | jq -r --arg title "$RULE_NAME" '.rules[] | select(.name==$title) | .confidence'`
        IMPACT_CUSTOMIZED=`cat ./rules.json | jq -r --arg title "$RULE_NAME" '.rules[] | select(.name==$title) | .customized_impact'`
        LIKELIHOOD_CUSTOMIZED=`cat ./rules.json | jq -r --arg title "$RULE_NAME" '.rules[] | select(.name==$title) | .customized_likelihood'`
        CONFIDENCE_CUSTOMIZED=`cat ./rules.json | jq -r --arg title "$RULE_NAME" '.rules[] | select(.name==$title) | .customized_confidence'`
        if [ $IMPACT_CUSTOMIZED = "false" -a $LIKELIHOOD_CUSTOMIZED = "false" -a $CONFIDENCE_CUSTOMIZED = "false" ]; then
            echo "  Skip."
            continue
        fi
        curl -X POST -sS \
            ${API_URL}/${ORG_ID}/rules/${RULE_NAME} \
            -H "Authorization: ${AUTHORIZATION}" \
            -H "API-Key: ${ORG_API_KEY}" \
            -H "Content-Type: application/json" \
            -H 'Accept: application/json' \
            -d '{"confidence_level": "'$CONFIDENCE'", "impact": "'$IMPACT'", "likelihood": "'$LIKELIHOOD'"}'
        sleep 1
    done < <(cat ./rules.json | jq -r '.rules[].name')
done < <(cat ./organizations.json | jq -r '.organizations[].organization_uuid')

exit 0

