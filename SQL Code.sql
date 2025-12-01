/* =====================================================================
   MedicalInfoSystem — Full Build & Ops Bundle (Single File)

   Sections (in order):
     1) CreateDBSchema
     2) CreateLoginAndUser
     3) Staff
     4) Patient
     5) AppointmentAndDiagnosis
     6) Audit
     7) Backup

   Notes:
   - Run in SQL Server Management Studio as a sysadmin for first-time setup.
   - You may keep the GO batch separators from source files.
   - Verify SQL Server service account has Modify permissions on the folders.
   - Adjust paths if your environment differs (Linux: /var/opt/mssql/... etc.).
   ===================================================================== */

SET NOCOUNT ON;
/* >>> BEGIN BUNDLE >>> */


/* =============================
   1) CreateDBSchema
   ============================= */

/*==============================================================================
 FILE 01: BUILD  DB, SCHEMAS, ROLES/USERS, KEYS/CERTS, TABLES, ENCRYPTED SEED
 Design (final):
   - STAFF PII      -> SYMMETRIC (AES-256) via SK_StaffPII (protected by Cert_StaffKEK)
   - PATIENT PII    -> SYMMETRIC (AES-256) via SK_PatientPII (protected by Cert_PatientKEK)
   - DIAGNOSIS TEXT -> ASYMMETRIC via Cert_Diag (EncryptByCert)
 Notes:
   - Run as sysadmin. Later files will add RLS, views, decrypt/encrypt SPs, and grants.
==============================================================================*/

------------------------------------------------------------
-- 0) Database
------------------------------------------------------------
IF DB_ID('MedicalInfoSystem') IS NULL
    CREATE DATABASE MedicalInfoSystem;
GO
USE MedicalInfoSystem;
GO

------------------------------------------------------------
-- 1) Schema
------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name = 'SecureData')
    EXEC('CREATE SCHEMA SecureData AUTHORIZATION dbo;');
GO

------------------------------------------------------------
-- 2) Logins & Users & Roles (demo passwords)
------------------------------------------------------------
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='SuperAdmin')
    CREATE LOGIN SuperAdmin WITH PASSWORD='P@ssSuperAdmin!2025', CHECK_POLICY=ON, DEFAULT_DATABASE=MedicalInfoSystem;

IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='D001')
    CREATE LOGIN D001 WITH PASSWORD='P@ssD001!', CHECK_POLICY=ON, DEFAULT_DATABASE=MedicalInfoSystem;
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='D002')
    CREATE LOGIN D002 WITH PASSWORD='P@ssD002!', CHECK_POLICY=ON, DEFAULT_DATABASE=MedicalInfoSystem;

IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='N001')
    CREATE LOGIN N001 WITH PASSWORD='P@ssN001!', CHECK_POLICY=ON, DEFAULT_DATABASE=MedicalInfoSystem;
IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='N002')
    CREATE LOGIN N002 WITH PASSWORD='P@ssN002!', CHECK_POLICY=ON, DEFAULT_DATABASE=MedicalInfoSystem;

IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name='P001')
    CREATE LOGIN P001 WITH PASSWORD='P@ssP001!', CHECK_POLICY=ON, DEFAULT_DATABASE=MedicalInfoSystem;
GO

USE MedicalInfoSystem;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='SuperAdmin') CREATE USER SuperAdmin FOR LOGIN SuperAdmin;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='D001')       CREATE USER D001       FOR LOGIN D001;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='D002')       CREATE USER D002       FOR LOGIN D002;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='N001')       CREATE USER N001       FOR LOGIN N001;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='N002')       CREATE USER N002       FOR LOGIN N002;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name='P001')       CREATE USER P001       FOR LOGIN P001;

IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='SuperAdmins') CREATE ROLE SuperAdmins;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='Doctors')     CREATE ROLE Doctors;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='Nurses')      CREATE ROLE Nurses;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='Patients')    CREATE ROLE Patients;

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members
    WHERE role_principal_id = USER_ID('SuperAdmins') AND member_principal_id = USER_ID('SuperAdmin'))
    ALTER ROLE SuperAdmins ADD MEMBER SuperAdmin;

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members
    WHERE role_principal_id = USER_ID('Doctors') AND member_principal_id = USER_ID('D001'))
    ALTER ROLE Doctors ADD MEMBER D001;
IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members
    WHERE role_principal_id = USER_ID('Doctors') AND member_principal_id = USER_ID('D002'))
    ALTER ROLE Doctors ADD MEMBER D002;

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members
    WHERE role_principal_id = USER_ID('Nurses') AND member_principal_id = USER_ID('N001'))
    ALTER ROLE Nurses ADD MEMBER N001;
IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members
    WHERE role_principal_id = USER_ID('Nurses') AND member_principal_id = USER_ID('N002'))
    ALTER ROLE Nurses ADD MEMBER N002;

IF NOT EXISTS (
    SELECT 1 FROM sys.database_role_members
    WHERE role_principal_id = USER_ID('Patients') AND member_principal_id = USER_ID('P001'))
    ALTER ROLE Patients ADD MEMBER P001;

-- Convenience (db_owner)
EXEC sp_addrolemember 'db_owner', 'SuperAdmin';
GO

------------------------------------------------------------
-- 3) Keys & Certificates
--    - DB Master Key protects private keys.
--    - Cert_StaffKEK protects symmetric key SK_StaffPII (Staff PII).
--    - Cert_PatientKEK protects symmetric key SK_PatientPII (Patient PII).
--    - Cert_Diag used directly for asymmetric EncryptByCert (Diagnosis text).
------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name='##MS_DatabaseMasterKey##')
    CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Str0ng!DBMK_P@ss_2025';
GO

IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name='Cert_StaffKEK')
    CREATE CERTIFICATE Cert_StaffKEK   WITH SUBJECT='Protector for Staff symmetric key';
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name='Cert_PatientKEK')
    CREATE CERTIFICATE Cert_PatientKEK WITH SUBJECT='Protector for Patient symmetric key';
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name='Cert_Diag')
    CREATE CERTIFICATE Cert_Diag       WITH SUBJECT='Asymmetric cert for Diagnosis details';
GO

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name='SK_StaffPII')
    CREATE SYMMETRIC KEY SK_StaffPII
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE Cert_StaffKEK;
IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name='SK_PatientPII')
    CREATE SYMMETRIC KEY SK_PatientPII
        WITH ALGORITHM = AES_256
        ENCRYPTION BY CERTIFICATE Cert_PatientKEK;
GO

------------------------------------------------------------
-- 4) Tables (ciphertext-at-rest columns)
------------------------------------------------------------
IF OBJECT_ID('SecureData.Staff','U') IS NULL
BEGIN
    CREATE TABLE SecureData.Staff (
        StaffID            VARCHAR(6)   NOT NULL CONSTRAINT PK_Staff PRIMARY KEY,
        StaffName          VARCHAR(100) NOT NULL,
        HomeAddress_Enc    VARBINARY(512)  NOT NULL, -- SYMMETRIC (SK_StaffPII)
        OfficePhone        VARCHAR(20)   NULL,        -- plaintext (directory)
        PersonalPhone_Enc  VARBINARY(256)  NULL,      -- SYMMETRIC (SK_StaffPII)
        Position           VARCHAR(20)   NULL         -- Doctor / Nurse
    );
END;

IF OBJECT_ID('SecureData.Patient','U') IS NULL
BEGIN
    CREATE TABLE SecureData.Patient (
        PatientID       VARCHAR(6)   NOT NULL CONSTRAINT PK_Patient PRIMARY KEY,
        PatientName     VARCHAR(100) NOT NULL,
        Phone_Enc       VARBINARY(512)   NULL,       -- SYMMETRIC (SK_PatientPII)
        HomeAddress_Enc VARBINARY(1024)  NOT NULL    -- SYMMETRIC (SK_PatientPII)
    );
END;

IF OBJECT_ID('SecureData.AppointmentAndDiagnosis','U') IS NULL
BEGIN
    CREATE TABLE SecureData.AppointmentAndDiagnosis (
        DiagID          INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AppointmentAndDiagnosis PRIMARY KEY,
        AppDateTime     DATETIME    NOT NULL,
        PatientID       VARCHAR(6)  NOT NULL,
        DoctorID        VARCHAR(6)  NOT NULL,
        DiagDetails_Enc VARBINARY(MAX) NULL           -- ASYMMETRIC (Cert_Diag)
        -- (FKs omitted intentionally; RLS will be added later)
    );
END;
GO

------------------------------------------------------------
-- 5) Seed sample data (encrypted)
------------------------------------------------------------
-- STAFF (symmetric)
OPEN SYMMETRIC KEY SK_StaffPII DECRYPTION BY CERTIFICATE Cert_StaffKEK;

IF NOT EXISTS (SELECT 1 FROM SecureData.Staff WHERE StaffID='D001')
BEGIN
    INSERT INTO SecureData.Staff
        (StaffID, StaffName, HomeAddress_Enc, OfficePhone, PersonalPhone_Enc, Position)
    VALUES
        ('D001','Dr. Ooi',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '12 Jalan Bukit, KL')),
            '03-11112222',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '012-3456789')),
            'Doctor'),
        ('D002','Dr. Bryan',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '88 Jalan Ampang, KL')),
            '03-11113333',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '011-2233445')),
            'Doctor'),
        ('N001','Nurse Britney',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '55 Jalan Klang Lama, KL')),
            '03-22224444',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '017-8877665')),
            'Nurse'),
        ('N002','Nurse Samantha',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '22 Jalan Pudu, KL')),
            '03-22225555',
            EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(VARBINARY(4000), '016-9988776')),
            'Nurse');
END;

CLOSE SYMMETRIC KEY SK_StaffPII;
GO

-- PATIENT (symmetric)
OPEN SYMMETRIC KEY SK_PatientPII DECRYPTION BY CERTIFICATE Cert_PatientKEK;

IF NOT EXISTS (SELECT 1 FROM SecureData.Patient WHERE PatientID='P001')
BEGIN
    INSERT INTO SecureData.Patient
        (PatientID, PatientName, Phone_Enc, HomeAddress_Enc)
    VALUES
        ('P001','Ali Musa',
            EncryptByKey(Key_GUID('SK_PatientPII'), CONVERT(VARBINARY(4000), '012-3456789')),
            EncryptByKey(Key_GUID('SK_PatientPII'), CONVERT(VARBINARY(4000), '22, Jalan Bukit, KL')));
END;

CLOSE SYMMETRIC KEY SK_PatientPII;
GO

-- APPOINTMENT & DIAGNOSIS (diag left NULL initially; asymmetric used when set)
IF NOT EXISTS (SELECT 1 FROM SecureData.AppointmentAndDiagnosis)
BEGIN
    INSERT INTO SecureData.AppointmentAndDiagnosis (AppDateTime, PatientID, DoctorID, DiagDetails_Enc)
    VALUES (DATEADD(day, 1, SYSUTCDATETIME()), 'P001', 'D001', NULL);
END;
GO

------------------------------------------------------------
-- 6) Lock down base tables (least-privilege in later files)
------------------------------------------------------------
REVOKE SELECT, INSERT, UPDATE, DELETE ON SecureData.Staff  FROM Doctors, Nurses, Patients;
REVOKE SELECT, INSERT, UPDATE, DELETE ON SecureData.Patient FROM Doctors, Nurses, Patients;
REVOKE SELECT, INSERT, UPDATE, DELETE ON SecureData.AppointmentAndDiagnosis FROM Doctors, Nurses, Patients;
GO

------------------------------------------------------------
-- 7) Structure sanity (no secrets exposed)
------------------------------------------------------------
SELECT 'Certs'  AS What, name FROM sys.certificates WHERE name IN ('Cert_StaffKEK','Cert_PatientKEK','Cert_Diag');
SELECT 'SymKeys' AS What, name FROM sys.symmetric_keys WHERE name IN ('SK_StaffPII','SK_PatientPII');
SELECT 'Tables' AS What, name FROM sys.tables WHERE schema_id = SCHEMA_ID('SecureData');
SELECT 'Roles'  AS What, name FROM sys.database_principals WHERE type='R' AND name IN ('SuperAdmins','Doctors','Nurses','Patients');
GO


-- ===== End of section: CreateDBSchema =====
GO


/* =============================
   2) CreateLoginAndUser
   ============================= */

/*==========================================================
Create SQL logins (server-level) and DB users (db-level)
for:
  Doctors: D001..D010
  Nurses : N001..N010
  Patients: P001..P020
Adds users to roles: Doctors, Nurses, Patients
Seeds Staff/Patient rows (encrypted) if missing
Run as: SuperAdmin (or higher)
==========================================================*/

------------------------------------------------------------
-- 1) Server-level: CREATE LOGINS (in master)
------------------------------------------------------------
USE master;
SET NOCOUNT ON;

DECLARE @i int, @id sysname, @pwd nvarchar(128), @sql nvarchar(max);

-- Doctors D001..D010
SET @i = 1;
WHILE @i <= 10
BEGIN
    SET @id = N'D' + RIGHT('000' + CAST(@i AS varchar(3)), 3);
    SET @pwd = N'P@ss' + @id + N'!2025';

    IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = @id)
    BEGIN
        SET @sql = N'CREATE LOGIN [' + @id + N'] WITH PASSWORD = N''' + REPLACE(@pwd,'''','''''') +
                   N''', CHECK_POLICY = ON, DEFAULT_DATABASE = MedicalInfoSystem;';
        EXEC (@sql);
        PRINT 'Created login ' + @id;
    END
    ELSE
        PRINT 'Login ' + @id + ' already exists (skipped).';

    SET @i += 1;
END

-- Nurses N001..N010
SET @i = 1;
WHILE @i <= 10
BEGIN
    SET @id = N'N' + RIGHT('000' + CAST(@i AS varchar(3)), 3);
    SET @pwd = N'P@ss' + @id + N'!2025';

    IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = @id)
    BEGIN
        SET @sql = N'CREATE LOGIN [' + @id + N'] WITH PASSWORD = N''' + REPLACE(@pwd,'''','''''') +
                   N''', CHECK_POLICY = ON, DEFAULT_DATABASE = MedicalInfoSystem;';
        EXEC (@sql);
        PRINT 'Created login ' + @id;
    END
    ELSE
        PRINT 'Login ' + @id + ' already exists (skipped).';

    SET @i += 1;
END

-- Patients P001..P020
SET @i = 1;
WHILE @i <= 20
BEGIN
    SET @id = N'P' + RIGHT('000' + CAST(@i AS varchar(3)), 3);
    SET @pwd = N'P@ss' + @id + N'!2025';

    IF NOT EXISTS (SELECT 1 FROM sys.sql_logins WHERE name = @id)
    BEGIN
        SET @sql = N'CREATE LOGIN [' + @id + N'] WITH PASSWORD = N''' + REPLACE(@pwd,'''','''''') +
                   N''', CHECK_POLICY = ON, DEFAULT_DATABASE = MedicalInfoSystem;';
        EXEC (@sql);
        PRINT 'Created login ' + @id;
    END
    ELSE
        PRINT 'Login ' + @id + ' already exists (skipped).';

    SET @i += 1;
END
GO

------------------------------------------------------------
-- 2) Database-level: CREATE USERS & ADD TO ROLES
------------------------------------------------------------
USE MedicalInfoSystem;
SET NOCOUNT ON;

-- Ensure roles exist
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='Doctors')  CREATE ROLE Doctors;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='Nurses')   CREATE ROLE Nurses;
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE type='R' AND name='Patients') CREATE ROLE Patients;

DECLARE @i int, @id sysname, @sql nvarchar(max);

-- Doctors D001..D010
SET @i = 1;
WHILE @i <= 10
BEGIN
    SET @id = N'D' + RIGHT('000' + CAST(@i AS varchar(3)), 3);

    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @id)
    BEGIN
        SET @sql = N'CREATE USER [' + @id + N'] FOR LOGIN [' + @id + N'];';
        EXEC (@sql);
        PRINT 'Created user ' + @id;
    END
    ELSE
        PRINT 'User ' + @id + ' already exists (skipped).';

    IF NOT EXISTS (
        SELECT 1
        FROM sys.database_role_members drm
        JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id AND r.name='Doctors'
        JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id AND m.name=@id
    )
    BEGIN
        SET @sql = N'ALTER ROLE Doctors ADD MEMBER [' + @id + N'];';
        EXEC (@sql);
        PRINT 'Added ' + @id + ' to Doctors';
    END
    ELSE
        PRINT @id + ' already in Doctors (skipped).';

    SET @i += 1;
END

-- Nurses N001..N010
SET @i = 1;
WHILE @i <= 10
BEGIN
    SET @id = N'N' + RIGHT('000' + CAST(@i AS varchar(3)), 3);

    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @id)
    BEGIN
        SET @sql = N'CREATE USER [' + @id + N'] FOR LOGIN [' + @id + N'];';
        EXEC (@sql);
        PRINT 'Created user ' + @id;
    END
    ELSE
        PRINT 'User ' + @id + ' already exists (skipped).';

    IF NOT EXISTS (
        SELECT 1
        FROM sys.database_role_members drm
        JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id AND r.name='Nurses'
        JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id AND m.name=@id
    )
    BEGIN
        SET @sql = N'ALTER ROLE Nurses ADD MEMBER [' + @id + N'];';
        EXEC (@sql);
        PRINT 'Added ' + @id + ' to Nurses';
    END
    ELSE
        PRINT @id + ' already in Nurses (skipped).';

    SET @i += 1;
END

-- Patients P001..P020
SET @i = 1;
WHILE @i <= 20
BEGIN
    SET @id = N'P' + RIGHT('000' + CAST(@i AS varchar(3)), 3);

    IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = @id)
    BEGIN
        SET @sql = N'CREATE USER [' + @id + N'] FOR LOGIN [' + @id + N'];';
        EXEC (@sql);
        PRINT 'Created user ' + @id;
    END
    ELSE
        PRINT 'User ' + @id + ' already exists (skipped).';

    IF NOT EXISTS (
        SELECT 1
        FROM sys.database_role_members drm
        JOIN sys.database_principals r ON r.principal_id = drm.role_principal_id AND r.name='Patients'
        JOIN sys.database_principals m ON m.principal_id = drm.member_principal_id AND m.name=@id
    )
    BEGIN
        SET @sql = N'ALTER ROLE Patients ADD MEMBER [' + @id + N'];';
        EXEC (@sql);
        PRINT 'Added ' + @id + ' to Patients';
    END
    ELSE
        PRINT @id + ' already in Patients (skipped).';

    SET @i += 1;
END
GO

------------------------------------------------------------
-- 3) Seed Staff & Patient rows (encrypted) if missing
------------------------------------------------------------
-- Ensure DBMK auto-opens (one-time)
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Str0ng!DBMK_P@ss_2025';
ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
CLOSE MASTER KEY;
GO

-- Open keys
OPEN SYMMETRIC KEY SK_StaffPII   DECRYPTION BY CERTIFICATE Cert_StaffKEK;
OPEN SYMMETRIC KEY SK_PatientPII DECRYPTION BY CERTIFICATE Cert_PatientKEK;
GO

-- Doctors D001..D010
DECLARE @i int = 1, @id varchar(6);
WHILE @i <= 10
BEGIN
    SET @id = 'D' + RIGHT('000' + CAST(@i AS varchar(3)), 3);
    IF NOT EXISTS (SELECT 1 FROM SecureData.Staff WHERE StaffID = @id)
    BEGIN
        INSERT INTO SecureData.Staff
            (StaffID, StaffName, HomeAddress_Enc, OfficePhone, PersonalPhone_Enc, Position)
        VALUES
            (
              @id,
              'Dr. ' + @id,
              EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(varbinary(4000), 'No. ' + CAST(@i AS varchar(10)) + ', Jalan Doktor, KL')),
              '03-11' + RIGHT('0000' + CAST(@i AS varchar(4)), 4),
              EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(varbinary(4000), '011-' + RIGHT('000000' + CAST(@i AS varchar(6)), 6))),
              'Doctor'
            );
        PRINT 'Inserted staff row ' + @id;
    END
    ELSE PRINT 'Staff row ' + @id + ' exists (skipped).';
    SET @i += 1;
END

-- Nurses N001..N010
SET @i = 1;
WHILE @i <= 10
BEGIN
    SET @id = 'N' + RIGHT('000' + CAST(@i AS varchar(3)), 3);
    IF NOT EXISTS (SELECT 1 FROM SecureData.Staff WHERE StaffID = @id)
    BEGIN
        INSERT INTO SecureData.Staff
            (StaffID, StaffName, HomeAddress_Enc, OfficePhone, PersonalPhone_Enc, Position)
        VALUES
            (
              @id,
              'Nurse ' + @id,
              EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(varbinary(4000), 'No. ' + CAST(@i AS varchar(10)) + ', Jalan Jururawat, KL')),
              '03-22' + RIGHT('0000' + CAST(@i AS varchar(4)), 4),
              EncryptByKey(Key_GUID('SK_StaffPII'), CONVERT(varbinary(4000), '017-' + RIGHT('000000' + CAST(@i AS varchar(6)), 6))),
              'Nurse'
            );
        PRINT 'Inserted staff row ' + @id;
    END
    ELSE PRINT 'Staff row ' + @id + ' exists (skipped).';
    SET @i += 1;
END

-- Patients P001..P020
SET @i = 1;
WHILE @i <= 20
BEGIN
    SET @id = 'P' + RIGHT('000' + CAST(@i AS varchar(3)), 3);
    IF NOT EXISTS (SELECT 1 FROM SecureData.Patient WHERE PatientID = @id)
    BEGIN
        INSERT INTO SecureData.Patient
            (PatientID, PatientName, Phone_Enc, HomeAddress_Enc)
        VALUES
            (
              @id,
              'Patient ' + @id,
              EncryptByKey(Key_GUID('SK_PatientPII'), CONVERT(varbinary(4000), '012-' + RIGHT('0000000' + CAST(@i AS varchar(7)), 7))),
              EncryptByKey(Key_GUID('SK_PatientPII'), CONVERT(varbinary(4000), 'No. ' + CAST(@i AS varchar(10)) + ', Jalan Pesakit, KL'))
            );
        PRINT 'Inserted patient row ' + @id;
    END
    ELSE PRINT 'Patient row ' + @id + ' exists (skipped).';
    SET @i += 1;
END
GO

-- Close keys
CLOSE SYMMETRIC KEY SK_PatientPII;
CLOSE SYMMETRIC KEY SK_StaffPII;
GO


-- ===== End of section: CreateLoginAndUser =====
GO


/* =============================
   3) Staff
   ============================= */

USE MedicalInfoSystem;
GO

/* =========================
   0) Master Key auto-open
   ========================= */
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Str0ng!DBMK_P@ss_2025';
ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
CLOSE MASTER KEY;
GO

/* ===============================================
   1) Crypto grants for decrypt/encrypt to work
   =============================================== */
GRANT VIEW DEFINITION ON CERTIFICATE::Cert_StaffKEK TO Doctors, Nurses;
GRANT CONTROL         ON CERTIFICATE::Cert_StaffKEK TO Doctors, Nurses;
GRANT VIEW DEFINITION ON SYMMETRIC KEY::SK_StaffPII   TO Doctors, Nurses;
GRANT CONTROL         ON SYMMETRIC KEY::SK_StaffPII   TO Doctors, Nurses;
GO

/* ===============================================
   2) View: self decrypted, others masked (**********)
   =============================================== */
IF OBJECT_ID('SecureData.vwStaff','V') IS NOT NULL
    DROP VIEW SecureData.vwStaff;
GO

CREATE VIEW SecureData.vwStaff
AS
SELECT
    s.StaffID,
    --CASE WHEN USER_NAME() = s.StaffID THEN s.StaffID ELSE '**********' END AS StaffID,
    s.StaffName,
    s.OfficePhone,
    CASE 
        WHEN USER_NAME() = s.StaffID THEN
            CONVERT(varchar(200),
                DecryptByKeyAutoCert(CERT_ID('Cert_StaffKEK'), NULL, s.HomeAddress_Enc)
            )
        ELSE '**********'
    END AS HomeAddress,
    CASE 
        WHEN USER_NAME() = s.StaffID THEN
            CONVERT(varchar(50),
                DecryptByKeyAutoCert(CERT_ID('Cert_StaffKEK'), NULL, s.PersonalPhone_Enc)
            )
        ELSE '**********'
    END AS PersonalPhone,
    CASE 
        WHEN USER_NAME() = s.StaffID THEN s.Position
        ELSE '**********'
    END AS Position
FROM SecureData.Staff AS s;
GO

GRANT SELECT, UPDATE ON OBJECT::SecureData.vwStaff TO Doctors;
GRANT SELECT, UPDATE ON OBJECT::SecureData.vwStaff TO Nurses;
GO

/* ===============================================
   3) Trigger: re-encrypt on update; only caller's row
   =============================================== */
IF OBJECT_ID('SecureData.tr_vwStaff_Update','TR') IS NOT NULL
    DROP TRIGGER SecureData.tr_vwStaff_Update;
GO

CREATE TRIGGER SecureData.tr_vwStaff_Update
ON SecureData.vwStaff
INSTEAD OF UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    DECLARE @me sysname = USER_NAME();

    IF UPDATE(Position)
    BEGIN
        RAISERROR('Updating Position is not allowed via this view.', 16, 1);
        RETURN;
    END

    IF NOT EXISTS (SELECT 1 FROM inserted WHERE StaffID = @me)
    BEGIN
        RAISERROR('You can only update your own details.', 16, 1);
        RETURN;
    END

    DECLARE
        @StaffName      varchar(100),
        @OfficePhone    varchar(20),
        @HomeAddress    varchar(200),
        @PersonalPhone  varchar(50);

    SELECT TOP (1)
        @StaffName     = i.StaffName,
        @OfficePhone   = i.OfficePhone,
        @HomeAddress   = i.HomeAddress,
        @PersonalPhone = i.PersonalPhone
    FROM inserted AS i
    WHERE i.StaffID = @me;

    OPEN SYMMETRIC KEY SK_StaffPII DECRYPTION BY CERTIFICATE Cert_StaffKEK;

    UPDATE s
    SET
        s.StaffName   = @StaffName,
        s.OfficePhone = @OfficePhone,
        s.HomeAddress_Enc =
            CASE
                WHEN @HomeAddress IS NULL OR @HomeAddress = '**********'
                    THEN s.HomeAddress_Enc
                ELSE EncryptByKey(Key_GUID('SK_StaffPII'),
                        CONVERT(VARBINARY(4000), @HomeAddress))
            END,
        s.PersonalPhone_Enc =
            CASE
                WHEN @PersonalPhone IS NULL OR @PersonalPhone = '**********'
                    THEN s.PersonalPhone_Enc
                ELSE EncryptByKey(Key_GUID('SK_StaffPII'),
                        CONVERT(VARBINARY(4000), @PersonalPhone))
            END
    FROM SecureData.Staff AS s
    WHERE s.StaffID = @me;

    CLOSE SYMMETRIC KEY SK_StaffPII;
END
GO

/* ===============================================
   4) Deny DELETE to staff roles (permissions layer)
   =============================================== */
DENY DELETE ON OBJECT::SecureData.Staff TO Doctors;
DENY DELETE ON OBJECT::SecureData.Staff TO Nurses;
GO

/* (Optional but nice UX): block DELETE via the view with a clear message */
IF OBJECT_ID('SecureData.tr_vwStaff_BlockDelete','TR') IS NOT NULL
    DROP TRIGGER SecureData.tr_vwStaff_BlockDelete;
GO
CREATE TRIGGER SecureData.tr_vwStaff_BlockDelete
ON SecureData.vwStaff
INSTEAD OF DELETE
AS
BEGIN
    RAISERROR('Deletion of staff records is not permitted.', 16, 1);
END
GO

/* ===============================================
   5) RLS: drop policy FIRST, then (re)create functions
   =============================================== */
IF EXISTS (SELECT 1 FROM sys.security_policies WHERE name = 'StaffRlsPolicy')
    DROP SECURITY POLICY SecureData.StaffRlsPolicy;
GO

IF OBJECT_ID('SecureData.fn_IsOwnStaffRow','IF') IS NOT NULL
    DROP FUNCTION SecureData.fn_IsOwnStaffRow;
GO
IF OBJECT_ID('SecureData.fn_CanDeleteStaff','IF') IS NOT NULL
    DROP FUNCTION SecureData.fn_CanDeleteStaff;
GO

/* Predicate: TRUE for owner (or SuperAdmins) — for UPDATE operations */
CREATE FUNCTION SecureData.fn_IsOwnStaffRow (@StaffID sysname)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_result
    WHERE @StaffID = USER_NAME()
       OR IS_MEMBER('SuperAdmins') = 1;
GO

/* Delete policy: ONLY SuperAdmins can delete (everyone else blocked) */
CREATE FUNCTION SecureData.fn_CanDeleteStaff (@StaffID sysname)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_result
    WHERE IS_MEMBER('SuperAdmins') = 1;
GO

/* ===============================================
   6) RLS policy (CREATE + ALTER pattern)
      - AFTER UPDATE      -> must own the row
      - BEFORE UPDATE     -> must own the row
      - BEFORE DELETE     -> only SuperAdmins may delete
   =============================================== */
CREATE SECURITY POLICY SecureData.StaffRlsPolicy
ADD BLOCK PREDICATE SecureData.fn_IsOwnStaffRow(StaffID)
    ON SecureData.Staff AFTER UPDATE
WITH (STATE = ON);
GO

ALTER SECURITY POLICY SecureData.StaffRlsPolicy
ADD BLOCK PREDICATE SecureData.fn_IsOwnStaffRow(StaffID)
    ON SecureData.Staff BEFORE UPDATE;
GO

ALTER SECURITY POLICY SecureData.StaffRlsPolicy
ADD BLOCK PREDICATE SecureData.fn_CanDeleteStaff(StaffID)
    ON SecureData.Staff BEFORE DELETE;
GO

-- Ensure policy is ON
ALTER SECURITY POLICY SecureData.StaffRlsPolicy WITH (STATE = ON);
GO


-- ===== End of section: Staff =====
GO


/* =============================
   4) Patient
   ============================= */

USE MedicalInfoSystem;
GO

/* =========================
   0) Ensure DBMK auto-open
   ========================= */
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Str0ng!DBMK_P@ss_2025';
ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
CLOSE MASTER KEY;
GO

/* =========================================================
   1) Crypto grants for Patient data (view decrypt/trigger)
   ========================================================= */
GRANT VIEW DEFINITION ON CERTIFICATE::Cert_PatientKEK TO Doctors, Nurses;
GRANT CONTROL         ON CERTIFICATE::Cert_PatientKEK TO Doctors, Nurses;
GRANT VIEW DEFINITION ON SYMMETRIC KEY::SK_PatientPII TO Doctors, Nurses;
GRANT CONTROL         ON SYMMETRIC KEY::SK_PatientPII TO Doctors, Nurses;
GO

/* =========================================================
   2) vwPatient: only ID, Name, decrypted Phone
   ========================================================= */
IF OBJECT_ID('SecureData.vwPatient','V') IS NOT NULL
    DROP VIEW SecureData.vwPatient;
GO
CREATE VIEW SecureData.vwPatient
AS
SELECT
    p.PatientID,
    p.PatientName,
    CONVERT(varchar(50),
        DecryptByKeyAutoCert(CERT_ID('Cert_PatientKEK'), NULL, p.Phone_Enc)
    ) AS Phone
FROM SecureData.Patient AS p;
GO

-- Grants for the view
GRANT SELECT ON OBJECT::SecureData.vwPatient TO Nurses;
GRANT UPDATE ON OBJECT::SecureData.vwPatient TO Nurses;
GRANT SELECT ON OBJECT::SecureData.vwPatient TO Doctors;
-- Explicitly keep Patients off the view
REVOKE SELECT ON OBJECT::SecureData.vwPatient FROM Patients;
REVOKE UPDATE ON OBJECT::SecureData.vwPatient FROM Patients;
GO

/* =========================================================
   3) UPDATE trigger: single-row, re-encrypt Phone
   ========================================================= */
IF OBJECT_ID('SecureData.tr_vwPatient_Update','TR') IS NOT NULL
    DROP TRIGGER SecureData.tr_vwPatient_Update;
GO
CREATE TRIGGER SecureData.tr_vwPatient_Update
ON SecureData.vwPatient
INSTEAD OF UPDATE
AS
BEGIN
    SET NOCOUNT ON;

    -- Only Nurses (or SuperAdmins) may update via the view
    IF IS_MEMBER('Nurses') <> 1 AND IS_MEMBER('SuperAdmins') <> 1
    BEGIN
        RAISERROR('Only Nurses may update patient details.', 16, 1);
        RETURN;
    END

    -- Enforce single-row updates (must specify a specific PatientID)
    DECLARE @rc int = (SELECT COUNT(*) FROM inserted);
    IF @rc <> 1
    BEGIN
        RAISERROR('Please target exactly one patient (e.g., WHERE PatientID = ''P001'').', 16, 1);
        RETURN;
    END

    -- Disallow changing PatientID
    IF UPDATE(PatientID)
    BEGIN
        RAISERROR('PatientID cannot be changed.', 16, 1);
        RETURN;
    END

    DECLARE
        @PatientID   varchar(6),
        @PatientName varchar(100),
        @Phone       varchar(50);

    SELECT TOP (1)
        @PatientID   = i.PatientID,
        @PatientName = i.PatientName,
        @Phone       = i.Phone
    FROM inserted AS i;

    OPEN SYMMETRIC KEY SK_PatientPII DECRYPTION BY CERTIFICATE Cert_PatientKEK;

    UPDATE p
       SET p.PatientName = COALESCE(@PatientName, p.PatientName),
           p.Phone_Enc   = CASE
                               WHEN @Phone IS NULL THEN NULL
                               ELSE EncryptByKey(Key_GUID('SK_PatientPII'),
                                      CONVERT(VARBINARY(4000), @Phone))
                           END
     FROM SecureData.Patient AS p
    WHERE p.PatientID = @PatientID;

    CLOSE SYMMETRIC KEY SK_PatientPII;
END
GO

/* =========================================================
   4) Patient self-service stored procedures (patients only)
   ========================================================= */
-- Clean up previous versions (optional)
IF OBJECT_ID('SecureData.usp_Patient_Self_Get', 'P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Patient_Self_Get;
IF OBJECT_ID('SecureData.usp_Patient_Self_Update', 'P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Patient_Self_Update;
GO

-- Returns own details (decrypted)
CREATE PROCEDURE SecureData.usp_Patient_Self_Get
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        PatientID,
        PatientName,
        CONVERT(varchar(50),
            DecryptByKeyAutoCert(CERT_ID('Cert_PatientKEK'), NULL, Phone_Enc)
        ) AS Phone,
        CONVERT(varchar(4000),
            DecryptByKeyAutoCert(CERT_ID('Cert_PatientKEK'), NULL, HomeAddress_Enc)
        ) AS HomeAddress
    FROM SecureData.Patient
    WHERE PatientID = SUSER_SNAME();   -- self
END;
GO

-- Updates own details (re-encrypts)
CREATE OR ALTER PROCEDURE SecureData.usp_Patient_Self_Update
    @PatientName   varchar(100),
    @Phone         varchar(50)    = NULL,
    @HomeAddress   varchar(4000)  = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @me sysname = SUSER_SNAME();

    /* 1) Ensure my row exists (RLS shows only my row anyway) */
    IF NOT EXISTS (SELECT 1 FROM SecureData.Patient WHERE PatientID = @me)
    BEGIN
        THROW 50001, 'No self row found to update.', 1;
    END

    /* 2) Re-encrypt and update my row */
    OPEN SYMMETRIC KEY SK_PatientPII DECRYPTION BY CERTIFICATE Cert_PatientKEK;

    UPDATE p
       SET PatientName     = @PatientName,
           Phone_Enc       = CASE WHEN @Phone IS NULL THEN NULL
                                  ELSE EncryptByKey(Key_GUID('SK_PatientPII'),
                                         CONVERT(VARBINARY(4000), @Phone)) END,
           HomeAddress_Enc = CASE WHEN @HomeAddress IS NULL THEN HomeAddress_Enc
                                  ELSE EncryptByKey(Key_GUID('SK_PatientPII'),
                                         CONVERT(VARBINARY(4000), @HomeAddress)) END
      FROM SecureData.Patient AS p
     WHERE p.PatientID = @me;

    CLOSE SYMMETRIC KEY SK_PatientPII;

    /* 3) Do NOT throw on no-change; just return current row */
    EXEC SecureData.usp_Patient_Self_Get;
END
GO

-- Patients can execute their self procedures; others cannot
GRANT EXECUTE ON SecureData.usp_Patient_Self_Get    TO Patients;
GRANT EXECUTE ON SecureData.usp_Patient_Self_Update TO Patients;
REVOKE EXECUTE ON SecureData.usp_Patient_Self_Get    FROM Doctors, Nurses;
REVOKE EXECUTE ON SecureData.usp_Patient_Self_Update FROM Doctors, Nurses;
GO

/* --- Module signing so patients dont need crypto perms --- */
-- 1) Create signer cert + mapped user (once)
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'Cert_PatientSelfSigner')
BEGIN
    CREATE CERTIFICATE Cert_PatientSelfSigner
        WITH SUBJECT = 'Signer for patient self SPs',
             EXPIRY_DATE = '2035-12-31';
END
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'PatientSelfSignerUser')
    CREATE USER PatientSelfSignerUser FROM CERTIFICATE Cert_PatientSelfSigner;
GO

-- 2) Grant ONLY the needed crypto rights to the signer user
GRANT CONTROL ON CERTIFICATE::Cert_PatientKEK TO PatientSelfSignerUser;
GRANT CONTROL ON SYMMETRIC KEY::SK_PatientPII TO PatientSelfSignerUser;
GO

-- 3) (Re)sign the two procedures (sign AFTER the final ALTER)
BEGIN TRY
    DROP SIGNATURE FROM OBJECT::SecureData.usp_Patient_Self_Get
        BY CERTIFICATE Cert_PatientSelfSigner;
END TRY BEGIN CATCH END CATCH;
BEGIN TRY
    DROP SIGNATURE FROM OBJECT::SecureData.usp_Patient_Self_Update
        BY CERTIFICATE Cert_PatientSelfSigner;
END TRY BEGIN CATCH END CATCH;

ADD SIGNATURE TO OBJECT::SecureData.usp_Patient_Self_Get
    BY CERTIFICATE Cert_PatientSelfSigner;
ADD SIGNATURE TO OBJECT::SecureData.usp_Patient_Self_Update
    BY CERTIFICATE Cert_PatientSelfSigner;
GO


/* =========================================================
   5) Consolidated RLS for Patient table (ONE policy)
   ========================================================= */
-- Drop any existing patient policies FIRST (to avoid conflict)
IF EXISTS (SELECT 1 FROM sys.security_policies WHERE name = 'PatientRlsPolicy')
    DROP SECURITY POLICY SecureData.PatientRlsPolicy;
IF EXISTS (SELECT 1 FROM sys.security_policies WHERE name = 'Policy_Patient_RLS')
    DROP SECURITY POLICY SecureData.Policy_Patient_RLS;
GO

-- Drop old predicate functions if present (any names)
IF OBJECT_ID('SecureData.fn_Patient_VisibleToCareTeam','IF') IS NOT NULL
    DROP FUNCTION SecureData.fn_Patient_VisibleToCareTeam;
IF OBJECT_ID('SecureData.fn_Patient_UpdateAllowed','IF') IS NOT NULL
    DROP FUNCTION SecureData.fn_Patient_UpdateAllowed;
IF OBJECT_ID('SecureData.fn_Patient_DeleteAllowed','IF') IS NOT NULL
    DROP FUNCTION SecureData.fn_Patient_DeleteAllowed;
GO

-- FILTER: Doctors/Nurses see all; Patients see self; Admin/db_owner see all
CREATE FUNCTION SecureData.fn_Patient_VisibleToCareTeam (@PatientID sysname)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_result
    WHERE IS_MEMBER('Doctors') = 1
       OR IS_MEMBER('Nurses') = 1
       OR IS_MEMBER('SuperAdmins') = 1
       OR IS_MEMBER('db_owner') = 1
       OR @PatientID = SUSER_SNAME();
GO

-- UPDATE allowed: Nurses (and SuperAdmins)
CREATE OR ALTER FUNCTION SecureData.fn_Patient_UpdateAllowed (@PatientID sysname)
RETURNS TABLE WITH SCHEMABINDING AS
RETURN
    SELECT 1 AS fn_result
    WHERE IS_MEMBER('Nurses') = 1
       OR IS_MEMBER('SuperAdmins') = 1
       OR @PatientID = SUSER_SNAME()
       OR IS_MEMBER('db_owner') = 1;
GO

-- DELETE allowed: SuperAdmins only
CREATE FUNCTION SecureData.fn_Patient_DeleteAllowed (@PatientID sysname)
RETURNS TABLE
WITH SCHEMABINDING
AS
RETURN
    SELECT 1 AS fn_result
    WHERE IS_MEMBER('SuperAdmins') = 1;
GO

-- Create ONE policy and add predicates (CREATE + ALTER pattern)
CREATE SECURITY POLICY SecureData.Policy_Patient_RLS
ADD FILTER PREDICATE SecureData.fn_Patient_VisibleToCareTeam(PatientID)
    ON SecureData.Patient
WITH (STATE = ON);
GO

ALTER SECURITY POLICY SecureData.Policy_Patient_RLS
ADD BLOCK PREDICATE SecureData.fn_Patient_UpdateAllowed(PatientID)
    ON SecureData.Patient BEFORE UPDATE;
GO
ALTER SECURITY POLICY SecureData.Policy_Patient_RLS
ADD BLOCK PREDICATE SecureData.fn_Patient_UpdateAllowed(PatientID)
    ON SecureData.Patient AFTER UPDATE;
GO
ALTER SECURITY POLICY SecureData.Policy_Patient_RLS
ADD BLOCK PREDICATE SecureData.fn_Patient_DeleteAllowed(PatientID)
    ON SecureData.Patient BEFORE DELETE;
GO
ALTER SECURITY POLICY SecureData.Policy_Patient_RLS WITH (STATE = ON);
GO

/* =========================================================
   6) Belt & suspenders: deny DELETE at permissions layer
   ========================================================= */
DENY DELETE ON OBJECT::SecureData.Patient TO Doctors, Nurses, Patients;
GO


-- ===== End of section: Patient =====
GO


/* =============================
   5) AppointmentAndDiagnosis
   ============================= */

USE MedicalInfoSystem;
GO

/* =========================
   0) Ensure DBMK auto-open
   ========================= */
OPEN MASTER KEY DECRYPTION BY PASSWORD = 'Str0ng!DBMK_P@ss_2025';
ALTER MASTER KEY ADD ENCRYPTION BY SERVICE MASTER KEY;
CLOSE MASTER KEY;
GO

/* =========================
   1) Minimal crypto grants
   =========================
   Doctors must be able to decrypt/encrypt diagnosis.
   Patients & Nurses get NO cert rights (patients decrypt via signed SP only).
*/
GRANT CONTROL ON CERTIFICATE::Cert_Diag TO Doctors;
GRANT VIEW DEFINITION ON CERTIFICATE::Cert_Diag TO Doctors;
-- (No grants to Nurses/Patients)
GO

/* =========================================================
   2) Views for Nurses / Doctors (join names; diag masked vs decrypted)
   ========================================================= */
IF OBJECT_ID('SecureData.vwAppointments_Nurse','V') IS NOT NULL
    DROP VIEW SecureData.vwAppointments_Nurse;
IF OBJECT_ID('SecureData.vwAppointments_Doctor','V') IS NOT NULL
    DROP VIEW SecureData.vwAppointments_Doctor;
GO

CREATE VIEW SecureData.vwAppointments_Nurse
AS
SELECT
    ad.DiagID,
    ad.AppDateTime,
    ad.PatientID,
    p.PatientName,
    ad.DoctorID,
    s.StaffName AS DoctorName,
    CASE 
        WHEN ad.DiagDetails_Enc IS NULL 
            THEN CAST(NULL AS nvarchar(max))
        ELSE N'**********'
    END AS Diagnosis
FROM SecureData.AppointmentAndDiagnosis AS ad
JOIN SecureData.Patient AS p ON p.PatientID = ad.PatientID
JOIN SecureData.Staff   AS s ON s.StaffID   = ad.DoctorID;
GO

CREATE VIEW SecureData.vwAppointments_Doctor
AS
SELECT
    ad.DiagID,
    ad.AppDateTime,
    ad.PatientID,
    p.PatientName,
    ad.DoctorID,
    s.StaffName AS DoctorName,
    CONVERT(nvarchar(max), DecryptByCert(CERT_ID('Cert_Diag'), ad.DiagDetails_Enc)) AS Diagnosis
FROM SecureData.AppointmentAndDiagnosis ad
JOIN SecureData.Patient p ON p.PatientID = ad.PatientID
JOIN SecureData.Staff   s ON s.StaffID   = ad.DoctorID;
GO

-- Grants
GRANT SELECT ON OBJECT::SecureData.vwAppointments_Nurse  TO Nurses;
GRANT SELECT ON OBJECT::SecureData.vwAppointments_Doctor TO Doctors;
-- Keep others off these views
REVOKE SELECT ON OBJECT::SecureData.vwAppointments_Nurse  FROM Patients;
REVOKE SELECT ON OBJECT::SecureData.vwAppointments_Doctor FROM Patients, Nurses;
GO

/* =========================================================
   3) Patient self view (decrypt via module signing; newest first)
   ========================================================= */
IF OBJECT_ID('SecureData.usp_Patient_Diagnosis_ListSelf','P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Patient_Diagnosis_ListSelf;
GO

CREATE PROCEDURE SecureData.usp_Patient_Diagnosis_ListSelf
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        ad.DiagID,
        ad.AppDateTime,
        ad.DoctorID,
        s.StaffName AS DoctorName,
        CONVERT(nvarchar(max), DecryptByCert(CERT_ID('Cert_Diag'), ad.DiagDetails_Enc)) AS Diagnosis
    FROM SecureData.AppointmentAndDiagnosis ad
    JOIN SecureData.Staff s ON s.StaffID = ad.DoctorID
    WHERE ad.PatientID = SUSER_SNAME()
    ORDER BY ad.AppDateTime DESC;
END
GO

GRANT EXECUTE ON SecureData.usp_Patient_Diagnosis_ListSelf TO Patients;
REVOKE EXECUTE ON SecureData.usp_Patient_Diagnosis_ListSelf FROM Doctors, Nurses;
GO

/* =========================================================
   4) Doctor: set/update diagnosis for own appointment (by DiagID)
   ========================================================= */
IF OBJECT_ID('SecureData.usp_Doctor_SetDiagnosis','P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Doctor_SetDiagnosis;
GO

CREATE PROCEDURE SecureData.usp_Doctor_SetDiagnosis
    @DiagID     int,
    @Diagnosis  nvarchar(max)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF IS_MEMBER('Doctors') <> 1 AND IS_MEMBER('SuperAdmins') <> 1
    BEGIN
        RAISERROR('Only Doctors may set diagnosis.', 16, 1);
        RETURN;
    END

    -- Must be the assigned doctor
    IF NOT EXISTS (
        SELECT 1
        FROM SecureData.AppointmentAndDiagnosis ad
        WHERE ad.DiagID = @DiagID
          AND (ad.DoctorID = SUSER_SNAME() OR IS_MEMBER('SuperAdmins') = 1)
    )
    BEGIN
        RAISERROR('Appointment not found or not assigned to you.', 16, 1);
        RETURN;
    END

    -- Update diagnosis (encrypt with Cert_Diag)
    UPDATE ad
       SET ad.DiagDetails_Enc = EncryptByCert(CERT_ID('Cert_Diag'),
                                   CONVERT(varbinary(max), @Diagnosis))
    FROM SecureData.AppointmentAndDiagnosis ad
    WHERE ad.DiagID = @DiagID;

    -- Return the updated row (decrypted)
    SELECT
        ad.DiagID,
        ad.AppDateTime,
        ad.PatientID,
        p.PatientName,
        ad.DoctorID,
        s.StaffName AS DoctorName,
        CONVERT(nvarchar(max), DecryptByCert(CERT_ID('Cert_Diag'), ad.DiagDetails_Enc)) AS Diagnosis
    FROM SecureData.AppointmentAndDiagnosis ad
    JOIN SecureData.Patient p ON p.PatientID = ad.PatientID
    JOIN SecureData.Staff   s ON s.StaffID   = ad.DoctorID
    WHERE ad.DiagID = @DiagID;
END
GO

GRANT EXECUTE ON SecureData.usp_Doctor_SetDiagnosis TO Doctors;
REVOKE EXECUTE ON SecureData.usp_Doctor_SetDiagnosis FROM Nurses, Patients;
GO

/* =========================================================
   5) Nurse: add/cancel/update appointment (only when diagnosis is NULL)
   ========================================================= */
IF OBJECT_ID('SecureData.usp_Nurse_AddAppointment','P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Nurse_AddAppointment;
IF OBJECT_ID('SecureData.usp_Nurse_CancelAppointment','P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Nurse_CancelAppointment;
IF OBJECT_ID('SecureData.usp_Nurse_UpdateAppointment','P') IS NOT NULL
    DROP PROCEDURE SecureData.usp_Nurse_UpdateAppointment;
GO

CREATE PROCEDURE SecureData.usp_Nurse_AddAppointment
    @PatientID   varchar(6),
    @DoctorID    varchar(6),
    @AppDateTime datetime
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF IS_MEMBER('Nurses') <> 1 AND IS_MEMBER('SuperAdmins') <> 1
    BEGIN
        RAISERROR('Only Nurses may add appointments.', 16, 1);
        RETURN;
    END

    -- Validate Patient exists
    IF NOT EXISTS (SELECT 1 FROM SecureData.Patient WHERE PatientID = @PatientID)
    BEGIN
        RAISERROR('PatientID not found.', 16, 1); RETURN;
    END
    -- Validate Doctor exists and is a Doctor
    IF NOT EXISTS (SELECT 1 FROM SecureData.Staff WHERE StaffID = @DoctorID AND Position = 'Doctor')
    BEGIN
        RAISERROR('DoctorID not found or not a Doctor.', 16, 1); RETURN;
    END

    INSERT INTO SecureData.AppointmentAndDiagnosis
        (AppDateTime, PatientID, DoctorID, DiagDetails_Enc)
    VALUES
        (@AppDateTime, @PatientID, @DoctorID, NULL);

    SELECT SCOPE_IDENTITY() AS NewDiagID;
END
GO

CREATE PROCEDURE SecureData.usp_Nurse_CancelAppointment
    @DiagID int
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF IS_MEMBER('Nurses') <> 1 AND IS_MEMBER('SuperAdmins') <> 1
    BEGIN
        RAISERROR('Only Nurses may cancel appointments.', 16, 1);
        RETURN;
    END

    DELETE FROM SecureData.AppointmentAndDiagnosis
     WHERE DiagID = @DiagID
       AND DiagDetails_Enc IS NULL;

    IF @@ROWCOUNT = 0
        RAISERROR('Cannot cancel: diagnosis already exists or appointment not found.', 16, 1);
END
GO

CREATE PROCEDURE SecureData.usp_Nurse_UpdateAppointment
    @DiagID       int,
    @NewDateTime  datetime
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF IS_MEMBER('Nurses') <> 1 AND IS_MEMBER('SuperAdmins') <> 1
    BEGIN
        RAISERROR('Only Nurses may update appointments.', 16, 1);
        RETURN;
    END

    UPDATE ad
       SET ad.AppDateTime = @NewDateTime
    FROM SecureData.AppointmentAndDiagnosis ad
    WHERE ad.DiagID = @DiagID
      AND ad.DiagDetails_Enc IS NULL;

    IF @@ROWCOUNT = 0
        RAISERROR('Cannot update time: diagnosis already exists or appointment not found.', 16, 1);
END
GO

GRANT EXECUTE ON SecureData.usp_Nurse_AddAppointment     TO Nurses;
GRANT EXECUTE ON SecureData.usp_Nurse_CancelAppointment  TO Nurses;
GRANT EXECUTE ON SecureData.usp_Nurse_UpdateAppointment  TO Nurses;
REVOKE EXECUTE ON SecureData.usp_Nurse_AddAppointment     FROM Doctors, Patients;
REVOKE EXECUTE ON SecureData.usp_Nurse_CancelAppointment  FROM Doctors, Patients;
REVOKE EXECUTE ON SecureData.usp_Nurse_UpdateAppointment  FROM Doctors, Patients;
GO

/* =========================================================
   6) Module signing so patients can decrypt (no cert grants)
   ========================================================= */
-- Reuse your PatientSelfSigner cert/user if already created,
-- else create them now.
IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'Cert_PatientSelfSigner')
BEGIN
    CREATE CERTIFICATE Cert_PatientSelfSigner
        WITH SUBJECT = 'Signer for patient self modules',
             EXPIRY_DATE = '2035-12-31';
END
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = 'PatientSelfSignerUser')
    CREATE USER PatientSelfSignerUser FROM CERTIFICATE Cert_PatientSelfSigner;
GO

-- Give signer rights ONLY to the diagnosis certificate (for DecryptByCert)
GRANT CONTROL ON CERTIFICATE::Cert_Diag TO PatientSelfSignerUser;
GO

-- (Re)sign patient self view procedure
BEGIN TRY
    DROP SIGNATURE FROM OBJECT::SecureData.usp_Patient_Diagnosis_ListSelf
        BY CERTIFICATE Cert_PatientSelfSigner;
END TRY BEGIN CATCH END CATCH;

ADD SIGNATURE TO OBJECT::SecureData.usp_Patient_Diagnosis_ListSelf
    BY CERTIFICATE Cert_PatientSelfSigner;
GO


-- ===== End of section: AppointmentAndDiagnosis =====
GO


/* =============================
   6) Audit
   ============================= */

/* ======================================================================
   MEDICALINFOSYSTEM — AUDIT SETUP (idempotent, permission-safe)
   Components:
     • Server Audit -> FILE (logins + breadth)
     • Database Audit Spec (SecureData scope)
     • DB-level DDL trigger -> Audit.DDLAudit  (calls proc EXECUTE AS OWNER)
     • Per-table DML triggers -> Audit.DMLAudit (WITH EXECUTE AS OWNER)
     • System-versioned temporal tables on 3 SecureData tables
   Prereq: Database + SecureData tables already created.
   Run as: SYSADMIN
   ====================================================================== */

--============================================================================
-- 0) SERVER AUDIT → FILE (safe default = SQL error-log folder)  **MUST run in master**
--============================================================================
USE master;
GO

DECLARE @UseErrorLogFolder bit = 0;   -- 1=reliable default; 0=use custom folder below
DECLARE @AuditDir nvarchar(4000);

IF @UseErrorLogFolder = 1
BEGIN
    DECLARE @ErrorLog nvarchar(4000) = CAST(SERVERPROPERTY('ErrorLogFileName') AS nvarchar(4000));
    DECLARE @BaseDir  nvarchar(4000) = LEFT(@ErrorLog, LEN(@ErrorLog) - CHARINDEX('\', REVERSE(@ErrorLog)) + 1);
    SET @AuditDir = @BaseDir + N'Audit\';
END
ELSE
BEGIN
    -- Make sure the SQL Server service account has write permission here:
    SET @AuditDir = N'C:\Users\user\Documents\APU\04 APD3F2502CS(DA)\Semester 2\Database Security\Assignment\MedicalInfoSystemAudit\';
END

-- ensure trailing slash + create folder (best-effort)
SET @AuditDir = @AuditDir + CASE WHEN RIGHT(@AuditDir,1) IN ('\','/') THEN '' ELSE '\' END;
BEGIN TRY EXEC master.dbo.xp_create_subdir @AuditDir; END TRY BEGIN CATCH END CATCH;

-- clean + (re)create server audit and spec
IF EXISTS (SELECT 1 FROM sys.server_audit_specifications WHERE name=N'ServerAuditSpec_MIS')
BEGIN
  ALTER SERVER AUDIT SPECIFICATION [ServerAuditSpec_MIS] WITH (STATE=OFF);
  DROP  SERVER AUDIT SPECIFICATION [ServerAuditSpec_MIS];
END;

IF EXISTS (SELECT 1 FROM sys.server_audits WHERE name=N'ServerAudit_MIS')
BEGIN
  ALTER SERVER AUDIT [ServerAudit_MIS] WITH (STATE=OFF);
  DROP  SERVER AUDIT [ServerAudit_MIS];
END;

DECLARE @dirEsc nvarchar(4000) = REPLACE(@AuditDir,'''','''''');
EXEC (N'
CREATE SERVER AUDIT [ServerAudit_MIS]
  TO FILE (FILEPATH = N''' + @dirEsc + N''',
           MAXSIZE = 1 GB, MAX_ROLLOVER_FILES = 20)
  WITH (QUEUE_DELAY = 1000, ON_FAILURE = CONTINUE);');

CREATE SERVER AUDIT SPECIFICATION [ServerAuditSpec_MIS]
FOR SERVER AUDIT [ServerAudit_MIS]
    ADD (SUCCESSFUL_LOGIN_GROUP),
    ADD (FAILED_LOGIN_GROUP),
    ADD (SERVER_PRINCIPAL_CHANGE_GROUP),
    ADD (SERVER_ROLE_MEMBER_CHANGE_GROUP),
    ADD (AUDIT_CHANGE_GROUP),
    ADD (BACKUP_RESTORE_GROUP);

ALTER SERVER AUDIT SPECIFICATION [ServerAuditSpec_MIS] WITH (STATE = ON);
ALTER SERVER AUDIT [ServerAudit_MIS] WITH (STATE = ON);
GO

-- from here on, continue inside the app database (rest of your Section 6 unchanged)
USE MedicalInfoSystem;
GO


--============================================================================
-- 1) DB OBJECTS (Audit schema + tables) + hardening
--============================================================================
GO
USE MedicalInfoSystem;
GO
IF NOT EXISTS (SELECT 1 FROM sys.schemas WHERE name=N'Audit')
  EXEC('CREATE SCHEMA Audit AUTHORIZATION dbo;');
ELSE
  ALTER AUTHORIZATION ON SCHEMA::Audit TO dbo;

IF OBJECT_ID(N'Audit.DDLAudit','U') IS NULL
BEGIN
  CREATE TABLE Audit.DDLAudit(
    DDLAuditID   bigint IDENTITY(1,1) PRIMARY KEY,
    PostTime     datetime2(7) NOT NULL DEFAULT SYSUTCDATETIME(),
    EventType    nvarchar(128) NOT NULL,
    ObjectSchema nvarchar(128) NULL,
    ObjectName   nvarchar(256) NULL,
    ObjectType   nvarchar(128) NULL,
    TSql         nvarchar(max) NULL,
    Actor        sysname       NOT NULL DEFAULT SUSER_SNAME(),
    EventXml     xml           NOT NULL
  );
END

IF OBJECT_ID(N'Audit.DMLAudit','U') IS NULL
BEGIN
  CREATE TABLE Audit.DMLAudit(
    DMLAuditID bigint IDENTITY(1,1) PRIMARY KEY,
    AtTime     datetime2(7) NOT NULL DEFAULT SYSUTCDATETIME(),
    TableName  sysname      NOT NULL,
    Action     char(1)      NOT NULL,      -- I/U/D
    KeyJson    nvarchar(2000) NOT NULL,
    BeforeJson nvarchar(max) NULL,
    AfterJson  nvarchar(max) NULL,
    Actor      sysname       NOT NULL DEFAULT SUSER_SNAME(),
    AppName    nvarchar(256) NULL DEFAULT APP_NAME(),
    HostName   nvarchar(256) NULL DEFAULT HOST_NAME(),
    SessionId  int           NOT NULL DEFAULT @@SPID
  );
END

IF OBJECT_ID(N'Audit.LogonAudit','U') IS NULL
BEGIN
  CREATE TABLE Audit.LogonAudit(
    LogonAuditID bigint IDENTITY(1,1) PRIMARY KEY,
    LoginTime  datetime2(7) NOT NULL DEFAULT SYSUTCDATETIME(),
    LoginName  sysname      NOT NULL,
    HostName   nvarchar(256) NULL,
    AppName    nvarchar(256) NULL,
    ClientIP   varchar(64)   NULL,
    SessionId  int           NOT NULL,
    Succeeded  bit           NULL
  );
END

-- lock evidence (inserts still succeed via OWNER context)
BEGIN TRY DENY INSERT, UPDATE, DELETE ON SCHEMA::Audit TO PUBLIC; END TRY BEGIN CATCH END CATCH;
BEGIN TRY DENY  UPDATE, DELETE ON SCHEMA::Audit TO PUBLIC; END TRY BEGIN CATCH END CATCH;
GO


--============================================================================
-- 2) DATABASE AUDIT SPEC (breadth + attempts in SecureData)
--============================================================================
IF EXISTS (SELECT 1 FROM sys.database_audit_specifications WHERE name=N'DB_Audit_MIS')
BEGIN
  ALTER DATABASE AUDIT SPECIFICATION [DB_Audit_MIS] WITH (STATE=OFF);
  DROP  DATABASE AUDIT SPECIFICATION [DB_Audit_MIS];
END
GO
CREATE DATABASE AUDIT SPECIFICATION [DB_Audit_MIS]
FOR SERVER AUDIT [ServerAudit_MIS]
    ADD (DATABASE_PERMISSION_CHANGE_GROUP),
    ADD (DATABASE_PRINCIPAL_CHANGE_GROUP),
    ADD (DATABASE_ROLE_MEMBER_CHANGE_GROUP),
    ADD (SCHEMA_OBJECT_ACCESS_GROUP),
    ADD (SELECT  ON SCHEMA::SecureData BY PUBLIC),
    ADD (INSERT  ON SCHEMA::SecureData BY PUBLIC),
    ADD (UPDATE  ON SCHEMA::SecureData BY PUBLIC),
    ADD (DELETE  ON SCHEMA::SecureData BY PUBLIC),
    ADD (EXECUTE ON SCHEMA::SecureData BY PUBLIC)
WITH (STATE = ON);
GO


--============================================================================
-- 3) HELPER PROC (EXECUTE AS OWNER) the DDL trigger will call
--============================================================================
-- create-or-alter pattern (avoids “already exists” and ordering issues)
IF OBJECT_ID('Audit.usp_WriteDDLAudit','P') IS NULL
    EXEC ('CREATE PROCEDURE Audit.usp_WriteDDLAudit AS RETURN 0;');
GO
ALTER PROCEDURE Audit.usp_WriteDDLAudit
  @EventXml xml,
  @Actor    sysname
WITH EXECUTE AS OWNER
AS
BEGIN
  SET NOCOUNT ON;
  INSERT Audit.DDLAudit(EventType,ObjectSchema,ObjectName,ObjectType,TSql,EventXml,Actor)
  SELECT
      @EventXml.value('(/EVENT_INSTANCE/EventType)[1]'               ,'nvarchar(128)'),
      @EventXml.value('(/EVENT_INSTANCE/SchemaName)[1]'              ,'nvarchar(128)'),
      @EventXml.value('(/EVENT_INSTANCE/ObjectName)[1]'              ,'nvarchar(256)'),
      @EventXml.value('(/EVENT_INSTANCE/ObjectType)[1]'              ,'nvarchar(128)'),
      @EventXml.value('(/EVENT_INSTANCE/TSQLCommand/CommandText)[1]' ,'nvarchar(max)'),
      @EventXml,
      @Actor;
END
GO
GRANT EXECUTE ON Audit.usp_WriteDDLAudit TO PUBLIC;
GO


--============================================================================
-- 4) DB-LEVEL DDL TRIGGER (CREATE must be 1st stmt in batch)
--============================================================================
IF EXISTS (SELECT 1 FROM sys.triggers WHERE name=N'TR_DDL_DB_Audit' AND parent_class=0)
    DROP TRIGGER TR_DDL_DB_Audit ON DATABASE;
GO
CREATE TRIGGER TR_DDL_DB_Audit
ON DATABASE
FOR DDL_DATABASE_LEVEL_EVENTS
AS
BEGIN
  SET NOCOUNT ON;

  DECLARE @x xml;       SET @x = CAST(EVENTDATA() AS xml);
  DECLARE @actor sysname; SET @actor = SUSER_SNAME();

  -- ignore events on our own Audit objects (prevents bootstrap noise)
  DECLARE @schema nvarchar(128) = @x.value('(/EVENT_INSTANCE/SchemaName)[1]','nvarchar(128)');
  DECLARE @obj    nvarchar(256) = @x.value('(/EVENT_INSTANCE/ObjectName)[1]' ,'nvarchar(256)');
  IF @schema = N'Audit' AND @obj IN (N'usp_WriteDDLAudit',N'DDLAudit',N'DMLAudit',N'LogonAudit',N'TR_DDL_DB_Audit') RETURN;

  EXEC Audit.usp_WriteDDLAudit @EventXml=@x, @Actor=@actor;
END;
GO


--============================================================================
-- 5) PER-TABLE DML TRIGGERS (SecureData.* with PK) → Audit.DMLAudit
--============================================================================
DECLARE @t table(SchemaName sysname, TableName sysname, TableId int, HasPK bit);
INSERT @t
SELECT s.name, t.name, t.object_id,
       CASE WHEN EXISTS (SELECT 1 FROM sys.indexes i WHERE i.object_id=t.object_id AND i.is_primary_key=1)
            THEN 1 ELSE 0 END
FROM sys.tables t
JOIN sys.schemas s ON s.schema_id=t.schema_id
WHERE s.name='SecureData' AND t.temporal_type <> 1;  -- skip history tables

DECLARE @Schema sysname, @Table sysname, @ObjId int, @HasPK bit;
DECLARE c CURSOR LOCAL FAST_FORWARD FOR SELECT SchemaName, TableName, TableId, HasPK FROM @t;
OPEN c; FETCH NEXT FROM c INTO @Schema, @Table, @ObjId, @HasPK;

WHILE @@FETCH_STATUS = 0
BEGIN
  IF @HasPK = 1
  BEGIN
    DECLARE @Trig sysname = N'TR_' + @Table + N'_DML_Audit';
    DECLARE @pkJoin nvarchar(max), @pkColsI nvarchar(max), @pkColsD nvarchar(max),
            @allColsI nvarchar(max), @allColsD nvarchar(max);

    -- PK lists & join
    SELECT
      @pkJoin = STRING_AGG(CONCAT('ISNULL(i.',QUOTENAME(c.name),', d.',QUOTENAME(c.name),')=ISNULL(d.',QUOTENAME(c.name),', i.',QUOTENAME(c.name),')'),' AND '),
      @pkColsI = STRING_AGG(CONCAT('i.',QUOTENAME(c.name)), ','),
      @pkColsD = STRING_AGG(CONCAT('d.',QUOTENAME(c.name)), ',')
    FROM sys.index_columns ic
    JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id
    JOIN sys.indexes  ix ON ix.object_id=ic.object_id AND ix.index_id=ic.index_id AND ix.is_primary_key=1
    WHERE ic.object_id=@ObjId;

    -- all (non-computed) columns
    SELECT
      @allColsI = STRING_AGG(CONCAT('i.',QUOTENAME(c.name)), ','),
      @allColsD = STRING_AGG(CONCAT('d.',QUOTENAME(c.name)), ',')
    FROM sys.columns c WHERE c.object_id=@ObjId AND c.is_computed=0;

    DECLARE @firstPK sysname =
    (SELECT TOP(1) c.name
     FROM sys.index_columns ic
     JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id
     JOIN sys.indexes  ix ON ix.object_id=ic.object_id AND ix.index_id=ic.index_id AND ix.is_primary_key=1
     WHERE ic.object_id=@ObjId ORDER BY ic.key_ordinal);

    DECLARE @ddl nvarchar(max) = N'
CREATE OR ALTER TRIGGER ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Trig) + N'
ON ' + QUOTENAME(@Schema) + N'.' + QUOTENAME(@Table) + N'
WITH EXECUTE AS OWNER
AFTER INSERT, UPDATE, DELETE
AS
BEGIN
  SET NOCOUNT ON;
  INSERT Audit.DMLAudit(AtTime, TableName, Action, KeyJson, BeforeJson, AfterJson, Actor, AppName, HostName, SessionId)
  SELECT
    SYSUTCDATETIME(),
    N''' + REPLACE(@Table,'''','''''') + N''',
    CASE WHEN i.' + QUOTENAME(@firstPK) + N' IS NOT NULL AND d.' + QUOTENAME(@firstPK) + N' IS NULL THEN ''I''
         WHEN i.' + QUOTENAME(@firstPK) + N' IS NULL AND d.' + QUOTENAME(@firstPK) + N' IS NOT NULL THEN ''D''
         ELSE ''U'' END,
    COALESCE( (SELECT ' + @pkColsI + N' FOR JSON PATH, WITHOUT_ARRAY_WRAPPER),
              (SELECT ' + @pkColsD + N' FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) ),
    CASE WHEN d.' + QUOTENAME(@firstPK) + N' IS NOT NULL
         THEN (SELECT ' + @allColsD + N' FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
    CASE WHEN i.' + QUOTENAME(@firstPK) + N' IS NOT NULL
         THEN (SELECT ' + @allColsI + N' FOR JSON PATH, WITHOUT_ARRAY_WRAPPER) END,
    SUSER_SNAME(), APP_NAME(), HOST_NAME(), @@SPID
  FROM inserted i
  FULL OUTER JOIN deleted d ON ' + @pkJoin + N';
END;';
    EXEC sys.sp_executesql @ddl;
  END

  FETCH NEXT FROM c INTO @Schema, @Table, @ObjId, @HasPK;
END
CLOSE c; DEALLOCATE c;
GO


--============================================================================
-- 6) SYSTEM-VERSIONED TEMPORAL on 3 SecureData tables (idempotent)
--============================================================================
-- helper to drop a default constraint on a column (safe)
CREATE OR ALTER PROCEDURE dbo.__drop_dc
  @tbl sysname,  -- 'SecureData.Patient'
  @col sysname   -- 'ValidFrom' / 'ValidTo'
AS
BEGIN
  SET NOCOUNT ON;
  DECLARE @schema sysname = PARSENAME(@tbl,2);
  DECLARE @table  sysname = PARSENAME(@tbl,1);
  DECLARE @objId  int     = OBJECT_ID(QUOTENAME(@schema)+'.'+QUOTENAME(@table));
  IF @objId IS NULL RETURN;

  DECLARE @dc sysname =
   (SELECT d.name
    FROM sys.default_constraints d
    JOIN sys.columns c ON c.object_id=d.parent_object_id AND c.column_id=d.parent_column_id
    WHERE d.parent_object_id=@objId AND c.name=@col);
  IF @dc IS NOT NULL
  BEGIN
    DECLARE @sql nvarchar(max) =
      N'ALTER TABLE ' + QUOTENAME(@schema) + N'.' + QUOTENAME(@table) +
      N' DROP CONSTRAINT ' + QUOTENAME(@dc) + N';';
    EXEC sys.sp_executesql @sql;
  END
END;
GO

DECLARE @tbl sysname, @base sysname, @hist sysname, @sql nvarchar(max);

DECLARE curT CURSOR LOCAL FAST_FORWARD FOR
SELECT N'SecureData.Patient' UNION ALL
SELECT N'SecureData.Staff'   UNION ALL
SELECT N'SecureData.AppointmentAndDiagnosis';
OPEN curT; FETCH NEXT FROM curT INTO @tbl;

WHILE @@FETCH_STATUS = 0
BEGIN
  IF OBJECT_ID(@tbl,'U') IS NOT NULL
     AND (SELECT temporal_type FROM sys.tables WHERE object_id=OBJECT_ID(@tbl))=0
  BEGIN
    SET @base = PARSENAME(@tbl,1);
    SET @hist = @base + N'History';

    -- drop period if it oddly exists; clean old columns
    IF EXISTS (SELECT 1 FROM sys.periods WHERE object_id = OBJECT_ID(@tbl))
      EXEC('ALTER TABLE ' + @tbl + ' DROP PERIOD FOR SYSTEM_TIME;');

    IF COL_LENGTH(@tbl,'ValidFrom') IS NOT NULL BEGIN EXEC dbo.__drop_dc @tbl,'ValidFrom'; EXEC('ALTER TABLE ' + @tbl + ' DROP COLUMN ValidFrom;'); END
    IF COL_LENGTH(@tbl,'ValidTo')   IS NOT NULL BEGIN EXEC dbo.__drop_dc @tbl,'ValidTo';   EXEC('ALTER TABLE ' + @tbl + ' DROP COLUMN ValidTo;');   END

    -- add period columns (try HIDDEN first)
    SET @sql = N'
BEGIN TRY
  ALTER TABLE ' + @tbl + N'
    ADD ValidFrom datetime2(7) GENERATED ALWAYS AS ROW START HIDDEN NOT NULL DEFAULT SYSUTCDATETIME(),
        ValidTo   datetime2(7) GENERATED ALWAYS AS ROW END   HIDDEN NOT NULL DEFAULT CONVERT(datetime2(7),''9999-12-31 23:59:59.9999999''),
        PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo);
END TRY
BEGIN CATCH
  ALTER TABLE ' + @tbl + N'
    ADD ValidFrom datetime2(7) GENERATED ALWAYS AS ROW START NOT NULL DEFAULT SYSUTCDATETIME(),
        ValidTo   datetime2(7) GENERATED ALWAYS AS ROW END   NOT NULL DEFAULT CONVERT(datetime2(7),''9999-12-31 23:59:59.9999999''),
        PERIOD FOR SYSTEM_TIME (ValidFrom, ValidTo);
END CATCH;';
    EXEC sys.sp_executesql @sql;

    -- turn on system-versioning with fixed history table name
    SET @sql = N'
ALTER TABLE ' + @tbl + N'
  SET (SYSTEM_VERSIONING = ON
       (HISTORY_TABLE = SecureData.' + QUOTENAME(@hist) + N',
        DATA_CONSISTENCY_CHECK = ON));';
    EXEC sys.sp_executesql @sql;

    PRINT 'Temporal enabled on ' + @tbl + ' → history: SecureData.' + @hist;
  END
  ELSE
    PRINT 'Skipped (already temporal or missing): ' + ISNULL(@tbl,'<null>');

  FETCH NEXT FROM curT INTO @tbl;
END
CLOSE curT; DEALLOCATE curT;
GO
/* =====================[ END OF AUDIT SETUP ]===================== */


-- Server audit ON?
USE master;
SELECT name,is_state_enabled FROM sys.server_audits WHERE name='ServerAudit_MIS';
SELECT name,is_state_enabled FROM sys.server_audit_specifications WHERE name='ServerAuditSpec_MIS';

-- DB audit spec ON?
USE MedicalInfoSystem;
SELECT name,is_state_enabled FROM sys.database_audit_specifications WHERE name='DB_Audit_MIS';

-- DML triggers exist on SecureData tables?
SELECT t.name AS trigger_name, s.name AS schema_name, o.name AS table_name, t.is_disabled
FROM sys.triggers t
JOIN sys.objects o ON t.parent_id=o.object_id
JOIN sys.schemas s ON o.schema_id=s.schema_id
WHERE s.name='SecureData' AND t.name LIKE 'TR_%_DML_Audit';


/* =====================[ Evidence Queries ]===================== */
/* 0) Status — all should be ON */
USE master;
SELECT name,is_state_enabled FROM sys.server_audits WHERE name=N'ServerAudit_MIS';
SELECT name,is_state_enabled FROM sys.server_audit_specifications WHERE name=N'ServerAuditSpec_MIS';
USE MedicalInfoSystem;
SELECT name,is_state_enabled FROM sys.database_audit_specifications WHERE name=N'DB_Audit_MIS';


/* 1) Enterprise Audit file – robust discovery + readback */
/* =======================[ ENTERPRISE AUDIT EVIDENCE ]======================= */
/* ===== Enterprise Audit readback — handle file vs folder correctly ===== */
USE master;

DECLARE @path    nvarchar(4000) =
(SELECT TOP(1) audit_file_path
   FROM sys.dm_server_audit_status
  WHERE name = N'ServerAudit_MIS' AND status = 1);

IF @path IS NULL
BEGIN
  PRINT 'ServerAudit_MIS is not started or not found.';
  SELECT name, status_desc, audit_file_path FROM sys.dm_server_audit_status;
  RETURN;
END

-- If DMV returned a file (ends with .sqlaudit), extract its directory; else use the path as-is.
DECLARE @dir nvarchar(4000);
IF @path LIKE N'%.sqlaudit'
BEGIN
  DECLARE @lastSlash int = LEN(@path) - CHARINDEX('\', REVERSE(@path)) + 1; -- position of last '\'
  SET @dir = SUBSTRING(@path, 1, @lastSlash);  -- includes trailing '\'
END
ELSE
BEGIN
  SET @dir = @path + CASE WHEN RIGHT(@path,1) IN ('\','/') THEN '' ELSE '\' END;
END

DECLARE @pattern nvarchar(4000) = @dir + N'*.sqlaudit';

SELECT [audit_file_path_from_DMV]=@path, [folder_we_will_read]=@dir, [pattern]=@pattern;

-- Now read the audit files
SELECT TOP 200 event_time, server_principal_name, database_name, schema_name, object_name,
       action_id, succeeded, statement
FROM sys.fn_get_audit_file(@pattern, DEFAULT, DEFAULT)
ORDER BY event_time DESC;

-- Your DB only
SELECT TOP 200 event_time, server_principal_name, database_name, schema_name, object_name,
       action_id, succeeded, statement
FROM sys.fn_get_audit_file(@pattern, DEFAULT, DEFAULT)
WHERE database_name = N'MedicalInfoSystem'
ORDER BY event_time DESC;

-- Failures only (attempts)
SELECT TOP 100 event_time, server_principal_name, database_name, schema_name, object_name,
       action_id, succeeded, statement
FROM sys.fn_get_audit_file(@pattern, DEFAULT, DEFAULT)
WHERE database_name = N'MedicalInfoSystem' AND succeeded = 0
ORDER BY event_time DESC;


/* 2) DDL trigger → Audit.DDLAudit */
USE MedicalInfoSystem;
SELECT TOP 20
  PostTime, EventType, ObjectSchema, ObjectName, ObjectType, Actor
FROM Audit.DDLAudit
ORDER BY PostTime DESC;

-- (optional) last 24h summary
SELECT EventType, COUNT(*) AS cnt
FROM Audit.DDLAudit
WHERE PostTime > DATEADD(day,-1,SYSUTCDATETIME())
GROUP BY EventType ORDER BY cnt DESC;

/* 3) DML triggers → Audit.DMLAudit (row deltas) */
-- Recent changes across SecureData tables
SELECT TOP 50
  AtTime, TableName, Action, KeyJson, Actor, AppName, HostName, SessionId
FROM Audit.DMLAudit
ORDER BY AtTime DESC;

-- Expand one example (Patient) to show keys and before/after
SELECT TOP 20
  AtTime, Action,
  JSON_VALUE(KeyJson,'$.PatientID')    AS PatientID,
  BeforeJson, AfterJson, Actor
FROM Audit.DMLAudit
WHERE TableName = N'Patient'
ORDER BY AtTime DESC;

/* 4) Temporal tables – point-in-time history */
/* ===== Temporal proof: status + timeline + AS-OF snapshots ===== */
/* ===========================[ TEMPORAL EVIDENCE ]=========================== */
USE MedicalInfoSystem;

-- 0) Status (screenshot this): temporal + history tables are present
SELECT t.name, t.temporal_type_desc, h.name AS HistoryTable
FROM sys.tables t
LEFT JOIN sys.tables h ON h.object_id = t.history_table_id
WHERE SCHEMA_NAME(t.schema_id)='SecureData'
  AND t.name IN (N'Patient', N'Staff', N'AppointmentAndDiagnosis');

-- 1) Make two versions for Patient (safe change + revert). If blocked by RLS, it will skip.
DECLARE @pid  sysname = (SELECT TOP(1) PatientID FROM SecureData.Patient ORDER BY PatientID);
DECLARE @orig nvarchar(200) = (SELECT PatientName FROM SecureData.Patient WHERE PatientID=@pid);

BEGIN TRY
  IF @orig IS NOT NULL
  BEGIN
    UPDATE SecureData.Patient
      SET PatientName = @orig + N' (temporal proof)'
    WHERE PatientID=@pid;

    WAITFOR DELAY '00:00:01';

    UPDATE SecureData.Patient
      SET PatientName = @orig
    WHERE PatientID=@pid;
  END
END TRY BEGIN CATCH
  PRINT 'Patient update skipped (possibly RLS). Proceeding with AppointmentAndDiagnosis demo.';
END CATCH;

-- 2) Guaranteed versions on AppointmentAndDiagnosis (insert -> update -> delete)
DECLARE @anyPatient sysname = (SELECT TOP(1) PatientID FROM SecureData.Patient ORDER BY PatientID);
DECLARE @anyDoctor sysname  = (SELECT TOP(1) StaffID   FROM SecureData.Staff  ORDER BY StaffID);
DECLARE @newDiagID int;

IF @anyPatient IS NOT NULL AND @anyDoctor IS NOT NULL
BEGIN
  INSERT INTO SecureData.AppointmentAndDiagnosis(AppDateTime, PatientID, DoctorID, DiagDetails_Enc)
  VALUES (SYSUTCDATETIME(), @anyPatient, @anyDoctor, NULL);
  SET @newDiagID = SCOPE_IDENTITY();

  UPDATE SecureData.AppointmentAndDiagnosis
    SET AppDateTime = DATEADD(minute, 5, AppDateTime)
  WHERE DiagID = @newDiagID;

  DELETE FROM SecureData.AppointmentAndDiagnosis
  WHERE DiagID = @newDiagID;
END

-- 3) Patient timeline (ALL versions)
SELECT PatientID, PatientName, ValidFrom, ValidTo
FROM SecureData.Patient FOR SYSTEM_TIME ALL
WHERE PatientID = @pid
ORDER BY ValidFrom;

-- 4) "AS OF" snapshots (compute timestamps first; then use variables in AS OF)
DECLARE @vmin datetime2(7) =
 (SELECT MIN(ValidFrom) FROM SecureData.Patient FOR SYSTEM_TIME ALL WHERE PatientID=@pid);
DECLARE @vmax datetime2(7) =
 (SELECT MAX(ValidFrom) FROM SecureData.Patient FOR SYSTEM_TIME ALL WHERE PatientID=@pid);

IF @vmin IS NOT NULL
BEGIN
  DECLARE @asofEarly  datetime2(7) = DATEADD(millisecond,1,@vmin);
  DECLARE @asofLatest datetime2(7) = DATEADD(millisecond,1,@vmax);

  SELECT 'AS OF early' AS label, PatientID, PatientName, ValidFrom, ValidTo
  FROM SecureData.Patient FOR SYSTEM_TIME AS OF @asofEarly
  WHERE PatientID=@pid;

  SELECT 'AS OF latest' AS label, PatientID, PatientName, ValidFrom, ValidTo
  FROM SecureData.Patient FOR SYSTEM_TIME AS OF @asofLatest
  WHERE PatientID=@pid;
END
ELSE
  PRINT 'No Patient versions yet. See AppointmentAndDiagnosis demo below.';

-- 5) AppointmentAndDiagnosis timeline (shows the insert/update/delete you just did)
IF @newDiagID IS NOT NULL
BEGIN
  SELECT DiagID, AppDateTime, PatientID, DoctorID, DiagDetails_Enc, ValidFrom, ValidTo
  FROM SecureData.AppointmentAndDiagnosis FOR SYSTEM_TIME ALL
  WHERE DiagID = @newDiagID
  ORDER BY ValidFrom;
END
ELSE
  PRINT 'No new DiagID was created (missing Patient/Doctor rows?).';


-- ===== End of section: Audit =====
GO


/* =============================
   7) Backup
   ============================= */

/* =====================================================================
   MedicalInfoSystem  TDE + Backups + SQL Agent Jobs (Single-batch)
   - No GO separators (variables remain in scope)
   - Minimal dynamic SQL, safe quoting
   - Fully qualified msdb objects
   ===================================================================== */
SET NOCOUNT ON;

-- === CONFIG ===
DECLARE @Db            sysname        = N'MedicalInfoSystem';
DECLARE @DbB           sysname        = N'[' + REPLACE(N'MedicalInfoSystem', N']', N']]') + N']'; -- bracket-quoted DB
DECLARE @BackupDir nvarchar(4000) = N'C:\Users\user\Documents\APU\04 APD3F2502CS(DA)\Semester 2\Database Security\Assignment\MedicalInfoSystemBackUp\';   -- ensure SQL Server service account has Modify rights
DECLARE @TDEPassword   nvarchar(200)  = N'Str0ng!DBMK_P@ss_2025';      -- master key password (master)
DECLARE @PrivKeyPass   nvarchar(200)  = N'Str0ng!PVK_P@ss_2025';       -- password for backed-up certificate's PVK

-- Ensure backup folder exists (best effort)
BEGIN TRY EXEC master.dbo.xp_create_subdir @BackupDir; END TRY BEGIN CATCH END CATCH;

-- === A) FULL recovery model ===
IF (SELECT recovery_model FROM sys.databases WHERE name=@Db) <> 1  -- 1 = FULL
BEGIN
    DECLARE @sqlRec nvarchar(400) = N'ALTER DATABASE ' + @DbB + N' SET RECOVERY FULL WITH NO_WAIT;';
    EXEC sys.sp_executesql @sqlRec;
END

-- === B) TDE protectors (in master) + BACKUP of the cert ===
USE master;

IF NOT EXISTS (SELECT 1 FROM sys.symmetric_keys WHERE name = '##MS_DatabaseMasterKey##')
BEGIN
    DECLARE @sqlMK nvarchar(max) = N'CREATE MASTER KEY ENCRYPTION BY PASSWORD = N''' 
        + REPLACE(@TDEPassword,'''','''''') + N''';';
    EXEC sys.sp_executesql @sqlMK;
END

IF NOT EXISTS (SELECT 1 FROM sys.certificates WHERE name = 'Cert_TDE_MIS')
BEGIN
    CREATE CERTIFICATE Cert_TDE_MIS
      WITH SUBJECT = 'TDE protector for MedicalInfoSystem';
END

DECLARE @Stamp   varchar(32)    = REPLACE(REPLACE(REPLACE(CONVERT(char(19),GETDATE(),120),':',''),'-',''),' ','_');
DECLARE @CerFile nvarchar(4000) = @BackupDir + N'Cert_TDE_MIS_' + @Stamp + N'.cer';
DECLARE @PvkFile nvarchar(4000) = @BackupDir + N'Cert_TDE_MIS_' + @Stamp + N'.pvk';

DECLARE @sqlBkpCert nvarchar(max) = 
N'BACKUP CERTIFICATE Cert_TDE_MIS
   TO FILE = N''' + REPLACE(@CerFile,'''','''''') + N'''
   WITH PRIVATE KEY (
        FILE = N''' + REPLACE(@PvkFile,'''','''''') + N''',
        ENCRYPTION BY PASSWORD = N''' + REPLACE(@PrivKeyPass,'''','''''') + N'''
   );';
EXEC sys.sp_executesql @sqlBkpCert;

-- === C) Create DEK in DB + turn TDE ON (tempdb will be encrypted too) ===
DECLARE @sqlCreateDEK nvarchar(max) = 
N'IF NOT EXISTS (SELECT 1 FROM sys.dm_database_encryption_keys WHERE database_id = DB_ID())
BEGIN
    CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256
        ENCRYPTION BY SERVER CERTIFICATE Cert_TDE_MIS;
END;';
EXEC ('USE ' + @DbB + '; ' + @sqlCreateDEK);

IF (SELECT is_encrypted FROM sys.databases WHERE name = @Db) = 0
BEGIN
    DECLARE @sqlEnc nvarchar(200) = N'ALTER DATABASE ' + @DbB + N' SET ENCRYPTION ON;';
    EXEC sys.sp_executesql @sqlEnc;
END

-- Evidence: 2 = encrypting, 3 = encrypted
SELECT db_name(database_id) AS DBName, encryption_state, encryptor_type
FROM sys.dm_database_encryption_keys
WHERE database_id IN (DB_ID(@Db), DB_ID('tempdb'));

-- === D) On-demand BACKUPS NOW (FULL smart, DIFF, LOG) ===
DECLARE @ts       varchar(32)    = REPLACE(REPLACE(REPLACE(CONVERT(char(19),GETDATE(),120),':',''),'-',''),' ','_');
DECLARE @fullFile nvarchar(4000) = @BackupDir + @Db + N'_FULL_' + @ts + N'.bak';
DECLARE @diffFile nvarchar(4000) = @BackupDir + @Db + N'_DIFF_' + @ts + N'.bak';
DECLARE @logFile  nvarchar(4000) = @BackupDir + @Db + N'_LOG_'  + @ts + N'.trn';

DECLARE @HasBaseFull bit =
    CASE WHEN EXISTS (
        SELECT 1 FROM msdb.dbo.backupset
        WHERE database_name=@Db AND type='D' AND is_copy_only=0
    ) THEN 1 ELSE 0 END;

DECLARE @sqlFull nvarchar(max);
IF @HasBaseFull = 0
    SET @sqlFull = N'BACKUP DATABASE ' + @DbB + N' TO DISK = @file WITH COMPRESSION, CHECKSUM, STATS=5;';
ELSE
    SET @sqlFull = N'BACKUP DATABASE ' + @DbB + N' TO DISK = @file WITH COPY_ONLY, COMPRESSION, CHECKSUM, STATS=5;';

EXEC sys.sp_executesql @sqlFull, N'@file nvarchar(4000)', @file=@fullFile;

DECLARE @sqlDiff nvarchar(max) = N'BACKUP DATABASE ' + @DbB + N' TO DISK = @file WITH DIFFERENTIAL, COMPRESSION, CHECKSUM, STATS=5;';
EXEC sys.sp_executesql @sqlDiff, N'@file nvarchar(4000)', @file=@diffFile;

DECLARE @sqlLog nvarchar(max)  = N'BACKUP LOG ' + @DbB + N' TO DISK = @file WITH COMPRESSION, CHECKSUM, STATS=5;';
EXEC sys.sp_executesql @sqlLog, N'@file nvarchar(4000)', @file=@logFile;

-- Verify the files we just wrote (uses variables, no hardcoded timestamps)
RESTORE VERIFYONLY FROM DISK = @fullFile;
RESTORE VERIFYONLY FROM DISK = @diffFile;
RESTORE VERIFYONLY FROM DISK = @logFile;

-- Evidence: recent backups & LSNs
SELECT TOP (20)
  b.database_name,
  CASE b.type WHEN 'D' THEN 'FULL' WHEN 'I' THEN 'DIFF' WHEN 'L' THEN 'LOG' END AS backup_type,
  b.is_copy_only, b.backup_start_date, b.backup_finish_date, mf.physical_device_name
FROM msdb.dbo.backupset b
JOIN msdb.dbo.backupmediafamily mf ON b.media_set_id = mf.media_set_id
WHERE b.database_name = @Db
ORDER BY b.backup_finish_date DESC;

SELECT TOP (10)
  b.type, b.is_copy_only, b.first_lsn, b.last_lsn, b.differential_base_lsn, b.differential_base_guid
FROM msdb.dbo.backupset b
WHERE b.database_name = @Db
ORDER BY b.backup_finish_date DESC;

-- === E) SQL Agent Jobs (FULL @ 02:00; DIFF / 4h; LOG / 15m) ===
DECLARE @JobFull sysname = N'APU_Backup_FULL_' + @Db;
DECLARE @JobDiff sysname = N'APU_Backup_DIFF_' + @Db;
DECLARE @JobLog  sysname = N'APU_Backup_LOG_'  + @Db;

DECLARE @SchFull sysname = N'SCH_Backup_FULL_Daily_02';
DECLARE @SchDiff sysname = N'SCH_Backup_DIFF_Every4h';
DECLARE @SchLog  sysname = N'SCH_Backup_LOG_Every15min';

-- step commands (generate timestamped filenames inside the job)
DECLARE @cmdFULL nvarchar(max) =
N'DECLARE @Dir nvarchar(4000)=N''' + REPLACE(@BackupDir,'''','''''') + N''';
  DECLARE @ts  varchar(32)=REPLACE(REPLACE(REPLACE(CONVERT(char(19),GETDATE(),120),'':'',''''),''-'',''''),'' '',''_'' );
  DECLARE @file nvarchar(4000)=@Dir+N''' + REPLACE(@Db,'''','''''') + N''' + N''_FULL_''+@ts+N''.bak'';
  BACKUP DATABASE ' + @DbB + N' TO DISK = @file WITH COMPRESSION, CHECKSUM, STATS=5;';

DECLARE @cmdDIFF nvarchar(max) =
N'DECLARE @Dir nvarchar(4000)=N''' + REPLACE(@BackupDir,'''','''''') + N''';
  DECLARE @ts  varchar(32)=REPLACE(REPLACE(REPLACE(CONVERT(char(19),GETDATE(),120),'':'',''''),''-'',''''),'' '',''_'' );
  DECLARE @file nvarchar(4000)=@Dir+N''' + REPLACE(@Db,'''','''''') + N''' + N''_DIFF_''+@ts+N''.bak'';
  BACKUP DATABASE ' + @DbB + N' TO DISK = @file WITH DIFFERENTIAL, COMPRESSION, CHECKSUM, STATS=5;';

DECLARE @cmdLOG nvarchar(max) =
N'DECLARE @Dir nvarchar(4000)=N''' + REPLACE(@BackupDir,'''','''''') + N''';
  DECLARE @ts  varchar(32)=REPLACE(REPLACE(REPLACE(CONVERT(char(19),GETDATE(),120),'':'',''''),''-'',''''),'' '',''_'' );
  DECLARE @file nvarchar(4000)=@Dir+N''' + REPLACE(@Db,'''','''''') + N''' + N''_LOG_''+@ts+N''.trn'';
  BACKUP LOG ' + @DbB + N' TO DISK = @file WITH COMPRESSION, CHECKSUM, STATS=5;';

-- FULL job (create or update)
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @JobFull)
BEGIN
  EXEC msdb.dbo.sp_add_job     @job_name=@JobFull, @enabled=1, @description=N'Nightly FULL backup (TDE)';
  EXEC msdb.dbo.sp_add_jobstep @job_name=@JobFull, @step_name=N'FULL', @subsystem=N'TSQL', @database_name=N'master', @command=@cmdFULL;

  IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysschedules WHERE name = @SchFull)
    EXEC msdb.dbo.sp_add_schedule @schedule_name=@SchFull, @freq_type=4, @freq_interval=1, @active_start_time=020000; -- daily 02:00

  IF NOT EXISTS (
      SELECT 1
      FROM msdb.dbo.sysjobschedules js
      JOIN msdb.dbo.sysschedules sc ON sc.schedule_id = js.schedule_id
      JOIN msdb.dbo.sysjobs      j  ON j.job_id = js.job_id
      WHERE j.name=@JobFull AND sc.name=@SchFull)
    EXEC msdb.dbo.sp_attach_schedule @job_name=@JobFull, @schedule_name=@SchFull;

  EXEC msdb.dbo.sp_add_jobserver  @job_name=@JobFull, @server_name=@@SERVERNAME;
END
ELSE
BEGIN
  EXEC msdb.dbo.sp_update_jobstep @job_name=@JobFull, @step_id=1, @step_name=N'FULL', @command=@cmdFULL;
END

-- DIFF job
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @JobDiff)
BEGIN
  EXEC msdb.dbo.sp_add_job     @job_name=@JobDiff, @enabled=1, @description=N'Differential backup every 4 hours (TDE)';
  EXEC msdb.dbo.sp_add_jobstep @job_name=@JobDiff, @step_name=N'DIFF', @subsystem=N'TSQL', @database_name=N'master', @command=@cmdDIFF;

  IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysschedules WHERE name = @SchDiff)
    EXEC msdb.dbo.sp_add_schedule @schedule_name=@SchDiff, @freq_type=4, @freq_interval=1,
                                  @freq_subday_type=8, @freq_subday_interval=4, @active_start_time=000000; -- every 4h

  IF NOT EXISTS (
      SELECT 1
      FROM msdb.dbo.sysjobschedules js
      JOIN msdb.dbo.sysschedules sc ON sc.schedule_id = js.schedule_id
      JOIN msdb.dbo.sysjobs      j  ON j.job_id = js.job_id
      WHERE j.name=@JobDiff AND sc.name=@SchDiff)
    EXEC msdb.dbo.sp_attach_schedule @job_name=@JobDiff, @schedule_name=@SchDiff;

  EXEC msdb.dbo.sp_add_jobserver @job_name=@JobDiff, @server_name=@@SERVERNAME;
END
ELSE
BEGIN
  EXEC msdb.dbo.sp_update_jobstep @job_name=@JobDiff, @step_id=1, @step_name=N'DIFF', @command=@cmdDIFF;
END

-- LOG job
IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysjobs WHERE name = @JobLog)
BEGIN
  EXEC msdb.dbo.sp_add_job     @job_name=@JobLog, @enabled=1, @description=N'Log backup every 15 minutes (TDE)';
  EXEC msdb.dbo.sp_add_jobstep @job_name=@JobLog, @step_name=N'LOG', @subsystem=N'TSQL', @database_name=N'master', @command=@cmdLOG;

  IF NOT EXISTS (SELECT 1 FROM msdb.dbo.sysschedules WHERE name = @SchLog)
    EXEC msdb.dbo.sp_add_schedule @schedule_name=@SchLog, @freq_type=4, @freq_interval=1,
                                  @freq_subday_type=4, @freq_subday_interval=15, @active_start_time=000000; -- every 15m

  IF NOT EXISTS (
      SELECT 1
      FROM msdb.dbo.sysjobschedules js
      JOIN msdb.dbo.sysschedules sc ON sc.schedule_id = js.schedule_id
      JOIN msdb.dbo.sysjobs      j  ON j.job_id = js.job_id
      WHERE j.name=@JobLog AND sc.name=@SchLog)
    EXEC msdb.dbo.sp_attach_schedule @job_name=@JobLog, @schedule_name=@SchLog;

  EXEC msdb.dbo.sp_add_jobserver  @job_name=@JobLog, @server_name=@@SERVERNAME;
END
ELSE
BEGIN
  EXEC msdb.dbo.sp_update_jobstep @job_name=@JobLog, @step_id=1, @step_name=N'LOG', @command=@cmdLOG;
END

-- Make jobs resilient to login changes
EXEC msdb.dbo.sp_update_job @job_name=@JobFull, @owner_login_name='sa';
EXEC msdb.dbo.sp_update_job @job_name=@JobDiff, @owner_login_name='sa';
EXEC msdb.dbo.sp_update_job @job_name=@JobLog , @owner_login_name='sa';

-- === F) Ops sanity ===
-- Agent service (Windows only; on Linux this DMV may be empty)
SELECT servicename, status_desc
FROM sys.dm_server_services
WHERE servicename LIKE 'SQL Server Agent%';

-- Next run times
SELECT
  j.name AS job_name,
  j.enabled AS job_enabled,
  sc.name AS schedule_name,
  sc.enabled AS schedule_enabled,
  CASE
    WHEN js.next_run_date IS NULL OR js.next_run_date = 0 THEN NULL
    ELSE CONVERT(datetime,
           STUFF(STUFF(CAST(js.next_run_date AS char(8)),7,0,'-'),5,0,'-') + ' ' +
           STUFF(STUFF(RIGHT('000000'+CAST(js.next_run_time AS varchar(6)),6),5,0,':'),3,0,':')
         )
  END AS next_run,
  CASE
    WHEN j.enabled = 0 THEN 'Job disabled'
    WHEN sc.enabled = 0 THEN 'Schedule disabled'
    WHEN js.next_run_date IS NULL OR js.next_run_date = 0 THEN 'Pending (Agent stopped or not computed yet)'
    ELSE 'Scheduled'
  END AS status
FROM msdb.dbo.sysjobs j
LEFT JOIN msdb.dbo.sysjobschedules js ON js.job_id = j.job_id
LEFT JOIN msdb.dbo.sysschedules   sc ON sc.schedule_id = js.schedule_id
WHERE j.name IN (N'APU_Backup_FULL_' + @Db, N'APU_Backup_DIFF_' + @Db, N'APU_Backup_LOG_' + @Db)
ORDER BY job_name;


-- ===== End of section: Backup =====
GO

/* <<< END BUNDLE <<< */
