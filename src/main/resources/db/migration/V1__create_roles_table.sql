CREATE TABLE roles (
                       id   BIGINT AUTO_INCREMENT PRIMARY KEY,
                       name VARCHAR(50) NOT NULL UNIQUE
);

INSERT INTO roles (name) VALUES
                             ('ADMIN'),
                             ('HR_MANAGER'),
                             ('RECRUITER'),
                             ('PAYROLL_OFFICER'),
                             ('MANAGER'),
                             ('EMPLOYEE');