# lcdb-ws
Prototyping repository for DB API

At this point very much experimental approach. What if the REST API logic would be implemented direction on database and the actual API endpoints autogenerated via PostgREST.

Authentication JWT would need to be generated by EDC. Thinking that tocken payload would contain role, exp, user type, study (optional), study role (optional).
