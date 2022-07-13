import * as dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import { Salt, parseSalt } from "../src/auth/password.service";

if (require.main === module) {
  dotenv.config();

  const { BCRYPT_SALT } = process.env;

  if (!BCRYPT_SALT) {
    throw new Error("BCRYPT_SALT environment variable must be defined");
  }

  const salt = parseSalt(BCRYPT_SALT);

  seed(salt).catch((error) => {
    console.error(error);
    process.exit(1);
  });
}
async function seed(bcryptSalt: Salt) {
  console.info("Seeding database...");

  const client = new PrismaClient();

  const queryEnableRowSecurity =
    'alter table public."User" enable row level security';
  await client.$queryRawUnsafe(queryEnableRowSecurity);

  const queryPolicySelect =
    "DO " +
    "$do$ " +
    "BEGIN " +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_policies " +
    "WHERE  policyname = 'Public users are viewable by everyone.') THEN " +
    'create policy "Public users are viewable by everyone." on public."User" for select using ( true );' +
    "END IF; " +
    "END " +
    "$do$; ";
  await client.$queryRawUnsafe(queryPolicySelect);

  const queryPolicyInsert =
    "DO " +
    "$do$ " +
    "BEGIN " +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_policies " +
    "WHERE  policyname = 'Users can insert their own users.') THEN " +
    'create policy "Users can insert their own users." on public."User" for insert with check ( auth.uid()::text = id );' +
    "END IF; " +
    "END " +
    "$do$; ";
  await client.$queryRawUnsafe(queryPolicyInsert);

  const queryPolicyupdate =
    "DO " +
    "$do$ " +
    "BEGIN " +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_policies " +
    "WHERE  policyname = 'Users can update own users.') THEN " +
    'create policy "Users can update own users." on public."User" for update using ( auth.uid()::text = id );' +
    "END IF; " +
    "END " +
    "$do$; ";
  await client.$queryRawUnsafe(queryPolicyupdate);

  const queryPolicySelectId =
    "DO " +
    "$do$ " +
    "BEGIN " +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_policies " +
    "WHERE  policyname = 'Users are viewable by users who created them.') THEN " +
    'create policy "Users are viewable by users who created them." on public."User" for select using ( auth.uid()::text = id );' +
    "END IF; " +
    "END " +
    "$do$; ";
  await client.$queryRawUnsafe(queryPolicySelectId);

  // create function that insert new row into  public.User
  const queryFunctionAddUser =
    "create or replace function public.handle_new_user() " +
    "returns trigger " +
    "language plpgsql " +
    "security definer set search_path = public " +
    "as $$ " +
    "begin " +
    'insert into public."User" (id,"createdAt","updatedAt",username,password,roles) ' +
    "values (new.id::text,new.created_at,new.updated_at,new.email,new.encrypted_password, ARRAY[new.role]) " +
    "ON CONFLICT (id) " +
    "DO " +
    'UPDATE SET "createdAt" = new.created_at,"updatedAt" = new.updated_at,username = new.email, ' +
    "password = new.encrypted_password,roles = ARRAY[new.role]; " +
    "return new; " +
    "end; " +
    "$$; ";
  await client.$queryRawUnsafe(queryFunctionAddUser);

  // create function that delete user when delete row from auth.user
  const queryFunctionDeleteUser =
    "create or replace function public.handle_delete_user() " +
    "returns trigger " +
    "language plpgsql " +
    "security definer set search_path = public " +
    "as $$ " +
    "begin " +
    'delete from public."User" where id = old.id; ' +
    "return old; " +
    "end; " +
    "$$; ";
  await client.$queryRawUnsafe(queryFunctionDeleteUser);

  const queryTriggerAddUser =
    "create or replace trigger on_auth_user_created " +
    "after insert or update on auth.users " +
    "for each row execute procedure public.handle_new_user() ";

  await client.$queryRawUnsafe(queryTriggerAddUser);

  const queryTriggerDeleteUser =
    "create or replace trigger on_auth_user_deleted " +
    "after delete on auth.users " +
    "for each row execute procedure public.handle_delete_user() ";

  await client.$queryRawUnsafe(queryTriggerDeleteUser);

  const createUser =
    "DO " +
    "$do$ " +
    "BEGIN " +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_user " +
    "WHERE  usename = 'user_postgres')Then " +
    "CREATE USER user_postgres WITH LOGIN PASSWORD 'user_postgres'; " +
    "END IF; " +
    "END " +
    "$do$; ";

  await client.$queryRawUnsafe(createUser);
  await client.$queryRawUnsafe(
    "alter user user_postgres with createdb createrole replication"
  );
  await client.$queryRawUnsafe(
    "GRANT ALL PRIVILEGES ON DATABASE postgres to user_postgres"
  );
  await client.$queryRawUnsafe("GRANT USAGE ON SCHEMA public TO user_postgres");
  await client.$queryRawUnsafe(
    "GRANT ALL PRIVILEGES ON SCHEMA public TO user_postgres"
  );
  await client.$queryRawUnsafe(
    "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO user_postgres"
  );
  await client.$queryRawUnsafe(
    "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO user_postgres"
  );

  const createRole =
    "DO " +
    "$do$ " +
    "BEGIN " +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_roles " +
    "WHERE  rolname = 'user')Then " +
    'create role "user" login noinherit;' +
    "END IF; " +
    "END " +
    "$do$; ";

  await client.$queryRawUnsafe(createRole);
  await client.$queryRawUnsafe('grant "user" to authenticator');
  await client.$queryRawUnsafe('GRANT USAGE ON SCHEMA public TO "user"');
  await client.$queryRawUnsafe(
    'GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "user"'
  );

  const createReqUserFunction =
    "create or replace function requesting_user_id() " +
    "returns text " +
    "language sql stable " +
    "as $$ " +
    "select nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::text; " +
    "$$;";
  await client.$queryRawUnsafe(createReqUserFunction);

  const setEntityUserColumn =
    "DO $$ " +
    "DECLARE " +
    "t_name VARCHAR; " +
    "c_name VARCHAR; " +
    "v_cnt int; " +
    "c1 CURSOR is ( " +
    "SELECT " +
    "tc.table_name, " +
    "kcu.column_name " +
    "FROM " +
    "information_schema.table_constraints AS tc " +
    "JOIN information_schema.key_column_usage AS kcu " +
    "ON tc.constraint_name = kcu.constraint_name " +
    "AND tc.table_schema = kcu.table_schema " +
    "JOIN information_schema.constraint_column_usage AS ccu " +
    "ON ccu.constraint_name = tc.constraint_name " +
    "AND ccu.table_schema = tc.table_schema " +
    "WHERE tc.constraint_type = 'FOREIGN KEY' AND ccu.table_name='User' AND ccu.table_schema ='public'); " +
    "BEGIN " +
    "OPEN c1; " +
    "LOOP " +
    "FETCH c1 INTO t_name,c_name; " +
    "EXIT when NOT FOUND; " +
    'EXECUTE format(\'ALTER TABLE "public"."%1$s" DISABLE ROW LEVEL SECURITY\',t_name); ' +
    "IF NOT EXISTS ( " +
    "SELECT FROM pg_catalog.pg_policies " +
    "WHERE  policyname = 'tenant_isolation_policy' and tablename = t_name ) THEN " +
    'EXECUTE format(\'CREATE POLICY tenant_isolation_policy ON "public"."%1$s" USING ("%2$s" = requesting_user_id())\',t_name,c_name); ' +
    "END IF; " +
    'EXECUTE format(\'ALTER TABLE "public"."%1$s" ALTER COLUMN "%2$s" SET DEFAULT requesting_user_id()\',t_name,c_name); ' +
    'EXECUTE format(\'ALTER TABLE "public"."%1$s" ENABLE ROW LEVEL SECURITY\',t_name); ' +
    "END LOOP; " +
    "CLOSE c1; " +
    "END $$; ";

  await client.$queryRawUnsafe(setEntityUserColumn);

  client.$disconnect();

  console.info("Seeding database with custom seed...");
  console.info("Seeded database successfully");
}
