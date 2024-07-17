-- API versioning via schema isolation
create schema wsv1;

-- Connect to database as non highly privileged (postgres) user
-- but different from the clinica system
create role authenticator noinherit login password 'apiauthenticatorpass';

-- Role for anonymous web requests
create role web_anon nologin;
-- Be able to switch from authenticator to web_anon 
grant web_anon to authenticator;
-- Role web_anon has rights to operate on v1 API schema
-- this has to be re-think, I think web anon should not have these rights
-- web_anon may have rights only on some generic ping API that does not exposes data
grant usage on schema wsv1 to web_anon;
--revoke usage on schema wsv1 from web_anon;

-- Role for authenticated web requests
create role web_auth nologin;
-- Be able to switch from authenticator to web_auth
grant web_auth to authenticator;

-- Authorization procedure (utils) schema
create schema wsauth;
-- Both roles can use it
grant usage on schema wsauth to web_anon, web_auth;

-- Here we want to check check whether user is authorized for API call on specific study
create or replace function auth.check_token() returns void
  language plpgsql
  as $$
begin
  if current_setting('request.jwt.claims', true)::json->>'email' =
     'disgruntled@mycompany.com' then
    raise insufficient_privilege
      using hint = 'Nope, we are on to you';
  end if;
end
$$;

-- Read API call for study subject
-- we call this as definer because our roles does not have permissions to public schema with EDC tables
create or replace function wsv1.read_study_subjects(study_identifier varchar) 
  returns setof public.study_subject 
  language sql 
  security definer set search_path = public
  as $$
select ss.*
  from public.study_subject as ss, public.study st
  where st.unique_identifier = study_identifier
  order by ss.label asc;
$$;
