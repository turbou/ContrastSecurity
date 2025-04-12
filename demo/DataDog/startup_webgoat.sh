export CONTRAST__API__TOKEN=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
java -javaagent:/Users/turbou/contrast/agent/java/contrast.jar \
-Dcontrast.server.environment=development \
-Dcontrast.server.name=MacBookPro16 \
-Dcontrast.agent.java.standalone_app_name=WebGoat2025-3 \
-Dcontrast.application.version=v2025.3 \
-Dcontrast.agent.contrast_working_dir=contrast-work/ \
-Dcontrast.agent.logger.level=INFO \
-Dcontrast.agent.polling.app_activity_ms=3000 \
-Dcontrast.agent.polling.server_activity_ms=3000 \
-Dcontrast.api.timeout_ms=1000 \
-jar ./webgoat-2025.3.jar
