# 1. Make Role for using PostgreSQL

## 1.1. access to DB with default admin account
`Bash`
`psql -U postgres`
if you can't access with postgres account, you can connect with this account.
`sudo -i -u postgres`
`psql`

## 1.2. generate new user with password
`SQL`
`CREATE ROLE username WITH LOGIN PASSWORD 'your-password-here';`

## 1.3. give db making privilage to user
`SQL`
`ALTER ROLE username CREATEDB;`
`\q`

# 2. Execute

## 2.1 Database mitigration
`Bash`
`sqlx database create # 만약 DB를 생성하지 않았다면 실행`
`sqlx migrate run`

## 2.2 execute backend-server
`cargo run`