CREATE CONSTRAINT unique_alert_id IF NOT EXISTS FOR (n:Alert) REQUIRE n.id IS UNIQUE;
CREATE CONSTRAINT unique_host_hostname IF NOT EXISTS FOR (n:Host) REQUIRE n.hostname IS UNIQUE;
CREATE CONSTRAINT unique_user_username IF NOT EXISTS FOR (n:User) REQUIRE n.username IS UNIQUE;
CREATE CONSTRAINT unique_process_uid IF NOT EXISTS FOR (n:Process) REQUIRE n.process_uid IS UNIQUE;
CREATE CONSTRAINT unique_file_uid IF NOT EXISTS FOR (n:File) REQUIRE n.file_uid IS UNIQUE;
CREATE CONSTRAINT unique_network_id IF NOT EXISTS FOR (n:Network) REQUIRE n.id IS UNIQUE;

CREATE INDEX idx_alert_timestamp IF NOT EXISTS FOR (n:Alert) ON (n.timestamp);
CREATE INDEX idx_process_start_time IF NOT EXISTS FOR (n:Process) ON (n.start_time);
