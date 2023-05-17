CREATE TABLE users ( 
	id                   INTEGER NOT NULL  PRIMARY KEY  ,
	username             VARCHAR(64) NOT NULL    ,
	password             VARCHAR(256) NOT NULL    ,
	apikey               VARCHAR(128) NOT NULL    ,
	CONSTRAINT unq_username UNIQUE ( username ),
	CONSTRAINT unq_apikey UNIQUE ( apikey )
 );

CREATE TABLE invites ( 
	id                   INTEGER NOT NULL  PRIMARY KEY  ,
	token                VARCHAR(128) NOT NULL    ,
	invited              INTEGER     ,
	FOREIGN KEY ( invited ) REFERENCES users( id ) ON DELETE CASCADE ON UPDATE CASCADE
 );

CREATE TABLE media ( 
	hash                 VARCHAR(25) NOT NULL  PRIMARY KEY  ,
	owner                INTEGER NOT NULL    ,
	added                INTEGER NOT NULL DEFAULT (unixepoch())   ,
	filename             VARCHAR(128) NOT NULL    ,
	mime                 VARCHAR(64) NOT NULL DEFAULT 'application/octet-stream'   ,
	file                 BLOB NOT NULL    ,
	embeddable_file      BLOB     ,
	FOREIGN KEY ( owner ) REFERENCES users( id ) ON DELETE CASCADE ON UPDATE CASCADE
 );

CREATE TABLE sessions ( 
	id                   INTEGER NOT NULL  PRIMARY KEY  ,
	user                 INTEGER NOT NULL    ,
	token                VARCHAR(128) NOT NULL    ,
	created              INTEGER NOT NULL DEFAULT (unixepoch())   ,
	CONSTRAINT unq_sessions UNIQUE ( token ),
	FOREIGN KEY ( user ) REFERENCES users( id ) ON DELETE CASCADE ON UPDATE CASCADE
 );

INSERT INTO invites (token) VALUES("xd");
INSERT INTO invites (token) VALUES("sex");
INSERT INTO invites (token) VALUES("lmao");
INSERT INTO invites (token) VALUES("rofl");
INSERT INTO invites (token) VALUES("kekw");
INSERT INTO invites (token) VALUES("hs");