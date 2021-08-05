from django.contrib import admin
from django import forms
from django.contrib import messages
from django.utils.translation import gettext_lazy as _
from nested_admin import NestedModelAdmin, NestedStackedInline, NestedTabularInline
from application.models import Redmine, RedmineVul, RedmineNote, RedmineLib, GoogleChat
from redminelib import Redmine as RedmineApi
from redminelib.exceptions import AuthError, ResourceNotFoundError

import json
import requests
import copy
import traceback

class RedmineNoteInlineForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'contrast_vul_id' in self.fields:
            self.fields['contrast_vul_id'].widget.attrs = {'size':23}

class RedmineNoteInline(NestedStackedInline):
    model = RedmineNote
    form = RedmineNoteInlineForm
    extra = 0
    ordering = ('-created_at',)
    readonly_fields = ('note', 'creator', 'created_at', 'updated_at', 'contrast_note_id', 'note_id')
    fieldsets = [ 
        (None, {'fields': ['note', ('creator', 'created_at', 'updated_at'), ('contrast_note_id', 'note_id')]}),
    ]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class RedmineVulInlineForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'contrast_vul_id' in self.fields:
            self.fields['contrast_vul_id'].widget.attrs = {'size':23}

class RedmineVulInline(NestedTabularInline):
    model = RedmineVul
    form = RedmineVulInlineForm
    extra = 0
    inlines = [
        RedmineNoteInline,
    ]
    readonly_fields = ('contrast_org_id', 'contrast_app_id', 'contrast_vul_id', 'issue_id')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class RedmineLibInlineForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'contrast_lib_lg' in self.fields:
            self.fields['contrast_lib_lg'].widget.attrs = {'size':16}

class RedmineLibInline(NestedTabularInline):
    model = RedmineLib
    form = RedmineLibInlineForm
    extra = 0
    readonly_fields = ('contrast_org_id', 'contrast_app_id', 'contrast_lib_lg', 'contrast_lib_id', 'issue_id')

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

class RedmineAdminForm(forms.ModelForm):
    tracker_id = forms.CharField(widget=forms.HiddenInput(), required=False)
    status_id_reported = forms.CharField(widget=forms.HiddenInput(), required=False)
    status_id_suspicious = forms.CharField(widget=forms.HiddenInput(), required=False)
    status_id_confirmed = forms.CharField(widget=forms.HiddenInput(), required=False)
    status_id_notaproblem = forms.CharField(widget=forms.HiddenInput(), required=False)
    status_id_remediated = forms.CharField(widget=forms.HiddenInput(), required=False)
    status_id_fixed = forms.CharField(widget=forms.HiddenInput(), required=False)
    severity_id_critical = forms.CharField(widget=forms.HiddenInput(), required=False)
    severity_id_high = forms.CharField(widget=forms.HiddenInput(), required=False)
    severity_id_medium = forms.CharField(widget=forms.HiddenInput(), required=False)
    severity_id_low = forms.CharField(widget=forms.HiddenInput(), required=False)
    severity_id_note = forms.CharField(widget=forms.HiddenInput(), required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['access_key'].widget.attrs = {'size':100}
        self.fields['tracker_id'].initial = self.instance.tracker_id

    def clean(self):
        cleaned_data = super().clean()
        if 'url' in cleaned_data and 'project_id' in cleaned_data and 'access_key' in cleaned_data:
            tracker_id = None
            try:
                redmine_api = RedmineApi(cleaned_data['url'], key=cleaned_data['access_key'])
                project = redmine_api.project.get(cleaned_data['project_id'])
                trackers = redmine_api.tracker.all()
                for tracker in trackers:
                    if tracker.name == cleaned_data['tracker_name']:
                        tracker_id = tracker.id
            except AuthError:
                raise forms.ValidationError(_('Authentication Error.'))
            except ResourceNotFoundError:
                raise forms.ValidationError(_('Project Not Found.'))
            except:
                traceback.print_exc()
                raise forms.ValidationError(_('An error occurred while processing check project.'))
            if tracker_id is None:
                raise forms.ValidationError(_('Tracker Not Found.'))
            else:
                cleaned_data['tracker_id'] = tracker_id
        return cleaned_data

@admin.register(Redmine)
class RedmineAdmin(NestedModelAdmin):
    save_on_top = True
    form = RedmineAdminForm
    search_fields = ('name', 'url',)
    actions = ['clear_mappings', 'delete_all_issues']
    list_display = ('name', 'url', 'vul_count', 'lib_count')
    inlines = [
        RedmineVulInline,
        RedmineLibInline,
    ]
    fieldsets = [ 
        (None, {'fields': ['name', 'url', ('project_id', 'tracker_name', 'tracker_id')]}),
        (_('Report User'), {'fields': ['access_key',]}),
        ('ステータスマッピング', {'fields': [
            ('status_name_reported', 'status_id_reported'),
            ('status_name_suspicious', 'status_id_suspicious'),
            ('status_name_confirmed', 'status_id_confirmed'),
            ('status_name_notaproblem', 'status_id_notaproblem'),
            ('status_name_remediated', 'status_id_remediated'),
            ('status_name_fixed', 'status_id_fixed'),
        ]}),
        ('優先度マッピング', {'fields': [
            ('severity_name_critical', 'severity_id_critical'),
            ('severity_name_high', 'severity_id_high'),
            ('severity_name_medium', 'severity_id_medium'),
            ('severity_name_low', 'severity_id_low'),
            ('severity_name_note', 'severity_id_note'),
        ]}),
    ]

    def vul_count(self, obj):
        return obj.vuls.count()
    vul_count.short_description = _('Vulnerability Count')

    def lib_count(self, obj):
        return obj.libs.count()
    lib_count.short_description = _('Library Count')

    def clear_mappings(self, request, queryset):
        selected = request.POST.getlist(admin.ACTION_CHECKBOX_NAME)
        redmines = Redmine.objects.filter(pk__in=selected)
        for redmine in redmines:
            redmine.vuls.all().delete()
            redmine.libs.all().delete()
        self.message_user(request, _('Vulnerability, library information cleared.'), level=messages.INFO)
    clear_mappings.short_description = _('Clear Vulnerability and Library Mapping')

    def delete_all_issues(self, request, queryset):
        selected = request.POST.getlist(admin.ACTION_CHECKBOX_NAME)
        redmines = Redmine.objects.filter(pk__in=selected)
        for redmine in redmines:
            redmine_api = RedmineApi(redmine.url, key=redmine.access_key)
            for mapping in RedmineVul.objects.all():
                issue = redmine_api.issue.get(mapping.issue_id)
                print(issue.subject)
                try:
                    issue.delete()
                except ResourceNotFoundError:
                    print('Error')
                except:
                    traceback.print_exc()
        self.message_user(request, _('Removed all Redmine issues.'), level=messages.INFO)
    delete_all_issues.short_description = _('Delete all Redmine issues')

    def get_actions(self, request):
        actions = super().get_actions(request)
        actions.pop('delete_selected')
        return actions

