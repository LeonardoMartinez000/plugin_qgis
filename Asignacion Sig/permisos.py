def concederPermisos(profesionales,usuarios,bd):
    query = """
    --QUITAR PERMISOS
    DO $$
    DECLARE
        r RECORD;
        s RECORD;
    BEGIN
        -- Revocar permisos en todos los esquemas
        FOR s IN
            SELECT nspname
            FROM pg_namespace
            WHERE nspname NOT IN ('pg_catalog', 'information_schema')
        LOOP
            FOR r IN
                SELECT rolname
                FROM pg_roles
                WHERE has_schema_privilege(rolname, s.nspname, 'USAGE')
            LOOP
                EXECUTE format('REVOKE CONNECT ON DATABASE %I FROM %I;', current_database(), r.rolname);
                EXECUTE format('REVOKE ALL ON SCHEMA %I FROM %I;', s.nspname, r.rolname);
                EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM %I;', s.nspname, r.rolname);
                EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM %I;', s.nspname, r.rolname);
                EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM %I;', s.nspname, r.rolname);
            END LOOP;
        END LOOP;
    END $$;
    
    /*DAR PERMISOS A PROFESIONAL SIG*/
    
    DO
    $$
    DECLARE
        schema_name text;
    BEGIN
        FOR schema_name IN
            SELECT nspname
            FROM pg_catalog.pg_namespace
            WHERE nspname NOT IN ('pg_catalog', 'information_schema')
        LOOP
            -- Otorgar permisos completos en cada esquema para el usuario_A
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT INSERT, UPDATE, DELETE, SELECT ON ALL TABLES IN SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT TRUNCATE, REFERENCES ON ALL TABLES IN SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT ALL ON ALL SEQUENCES IN SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT ALL ON ALL FUNCTIONS IN SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT CREATE ON SCHEMA %I TO {profesionales}', schema_name);
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO {profesionales}', schema_name);
        END LOOP;

        -- Permiso de creación y eliminación de tablas en la base de datos para usuario_A
        GRANT CREATE, TEMPORARY, CONNECT ON DATABASE "{bd}" TO {profesionales};
    END
    $$;

    /*DAR PERMISOS A DIGITALIZADORES*/

    GRANT CONNECT ON DATABASE "{bd}" TO latam_alex_camelo, {usuarios};
    
    DO
    $$
    DECLARE
        schema_record RECORD;
        schemas CURSOR FOR 
            SELECT schema_name 
            FROM information_schema.schemata 
            WHERE schema_name NOT IN ('information_schema', 'pg_catalog', 'pg_toast') 
            AND schema_name NOT LIKE 'pg_temp%';
    BEGIN
        FOR schema_record IN schemas LOOP
            EXECUTE format('GRANT USAGE ON SCHEMA %I TO latam_alex_camelo, {usuarios};', schema_record.schema_name);
            EXECUTE format('GRANT DELETE, SELECT, UPDATE, INSERT ON ALL TABLES IN SCHEMA %I TO latam_alex_camelo, {usuarios};', schema_record.schema_name);
            EXECUTE format('GRANT ALL ON ALL SEQUENCES IN SCHEMA %I TO latam_alex_camelo, {usuarios};', schema_record.schema_name);
            EXECUTE format('GRANT ALL ON ALL FUNCTIONS IN SCHEMA %I TO latam_alex_camelo, {usuarios};', schema_record.schema_name);
        END LOOP;
    END;
    $$;

    """.format(bd=bd, profesionales=profesionales, usuarios=usuarios)

    return query


def obtenerUsuariosYPermisos(host, bd, usuario, contrasena):
    """
    Obtiene lista de usuarios que tienen permisos EXPLÍCITOS en tablas (SELECT, INSERT, UPDATE, DELETE)
    Solo muestra permisos directamente otorgados, no heredados
    Retorna lista de tuplas: (usuario, permisos_string)
    """
    import psycopg2
    
    usuarios_permisos = []
    
    try:
        conn = psycopg2.connect(
            host=host, 
            database=bd, 
            user=usuario, 
            password=contrasena, 
            port='5432'
        )
        cursor = conn.cursor()
        
        # Consulta para obtener SOLO permisos explícitamente otorgados en tablas
        query = """
        SELECT DISTINCT
            grantee as usuario,
            string_agg(DISTINCT privilege_type, ', ' ORDER BY privilege_type) as permisos_tablas
        FROM information_schema.role_table_grants
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            AND grantee NOT IN ('pg_database_owner', 'postgres')
            AND privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
        GROUP BY grantee
        ORDER BY grantee;
        """
        
        cursor.execute(query)
        resultados = cursor.fetchall()
        
        for row in resultados:
            usuario = row[0]
            permisos_tablas = row[1] if row[1] else 'Sin permisos'
            
            # Crear string con permisos en tablas
            permisos_str = f"Permisos: {permisos_tablas}"
            usuarios_permisos.append((usuario, permisos_str))
        
        cursor.close()
        conn.close()
        
        return usuarios_permisos
    
    except Exception as e:
        raise Exception(f"Error al obtener usuarios: {str(e)}")


def revocarPermisosUsuarios(host, bd, usuario, contrasena, usuarios_a_revocar):
    """
    Revoca permisos a usuarios específicos
    usuarios_a_revocar: lista de nombres de usuarios
    """
    import psycopg2
    
    try:
        conn = psycopg2.connect(
            host=host, 
            database=bd, 
            user=usuario, 
            password=contrasena, 
            port='5432'
        )
        cursor = conn.cursor()
        
        for user in usuarios_a_revocar:
            # Revocar permisos en esquemas usando información_schema
            revoke_query = f"""
            SELECT 'REVOKE ALL ON SCHEMA "' || schema_name || '" FROM "{user}";' as cmd
            FROM information_schema.schemata
            WHERE schema_name NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            """
            
            cursor.execute(revoke_query)
            revoke_commands = cursor.fetchall()
            
            for cmd_tuple in revoke_commands:
                if cmd_tuple and cmd_tuple[0]:
                    try:
                        cursor.execute(cmd_tuple[0])
                    except:
                        pass
            
            # Revocar permisos en tablas
            revoke_tables_query = f"""
            SELECT 'REVOKE ALL ON TABLE "' || table_schema || '"."' || table_name || '" FROM "{user}";' as cmd
            FROM information_schema.tables
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            """
            
            cursor.execute(revoke_tables_query)
            revoke_table_commands = cursor.fetchall()
            
            for cmd_tuple in revoke_table_commands:
                if cmd_tuple and cmd_tuple[0]:
                    try:
                        cursor.execute(cmd_tuple[0])
                    except:
                        pass
            
            # Revocar conexión a la BD
            try:
                cursor.execute(f'REVOKE CONNECT ON DATABASE "{bd}" FROM "{user}";')
            except:
                pass
        
        conn.commit()
        cursor.close()
        conn.close()
        
        return True
    
    except Exception as e:
        raise Exception(f"Error al revocar permisos: {str(e)}")


def obtenerPermisosDetallados(host, bd, usuario, contrasena, usuario_objetivo):
    """
    Obtiene los permisos EXPLÍCITOS (SELECT, INSERT, UPDATE, DELETE) de un usuario
    en las tablas de la base de datos, organizados por esquema y tabla
    Retorna un diccionario con los permisos
    """
    import psycopg2
    
    try:
        conn = psycopg2.connect(
            host=host, 
            database=bd, 
            user=usuario, 
            password=contrasena, 
            port='5432'
        )
        cursor = conn.cursor()
        
        # Consulta para obtener permisos EXPLÍCITOS del usuario en tablas
        query = f"""
        SELECT 
            CASE WHEN COUNT(CASE WHEN privilege_type = 'SELECT' THEN 1 END) > 0 THEN true ELSE false END as tiene_select,
            CASE WHEN COUNT(CASE WHEN privilege_type = 'INSERT' THEN 1 END) > 0 THEN true ELSE false END as tiene_insert,
            CASE WHEN COUNT(CASE WHEN privilege_type = 'UPDATE' THEN 1 END) > 0 THEN true ELSE false END as tiene_update,
            CASE WHEN COUNT(CASE WHEN privilege_type = 'DELETE' THEN 1 END) > 0 THEN true ELSE false END as tiene_delete
        FROM information_schema.role_table_grants
        WHERE grantee = '{usuario_objetivo}'
            AND table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            AND privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE');
        """
        
        cursor.execute(query)
        resultado = cursor.fetchone()
        
        # Consulta para obtener detalles de cada tabla y sus permisos
        detalles_query = f"""
        SELECT 
            table_schema,
            table_name,
            BOOL_OR(CASE WHEN privilege_type = 'SELECT' THEN true ELSE false END) as tiene_select,
            BOOL_OR(CASE WHEN privilege_type = 'INSERT' THEN true ELSE false END) as tiene_insert,
            BOOL_OR(CASE WHEN privilege_type = 'UPDATE' THEN true ELSE false END) as tiene_update,
            BOOL_OR(CASE WHEN privilege_type = 'DELETE' THEN true ELSE false END) as tiene_delete
        FROM information_schema.role_table_grants
        WHERE grantee = '{usuario_objetivo}'
            AND table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
            AND privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
        GROUP BY table_schema, table_name
        ORDER BY table_schema, table_name;
        """
        
        cursor.execute(detalles_query)
        detalles_resultados = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        # Validar resultado
        if resultado is None or len(resultado) == 0:
            return {
                'SELECT': False,
                'INSERT': False,
                'UPDATE': False,
                'DELETE': False,
                'tablas': []
            }
        
        return {
            'SELECT': bool(resultado[0]) if resultado[0] is not None else False,
            'INSERT': bool(resultado[1]) if resultado[1] is not None else False,
            'UPDATE': bool(resultado[2]) if resultado[2] is not None else False,
            'DELETE': bool(resultado[3]) if resultado[3] is not None else False,
            'tablas': detalles_resultados if detalles_resultados else []
        }
    
    except Exception as e:
        raise Exception(f"Error al obtener permisos detallados: {str(e)}")


def obtenerTablasBaseDatos(host, bd, usuario, contrasena):
    """
    Obtiene todas las tablas de la base de datos
    Retorna lista de tuplas (esquema, tabla)
    """
    import psycopg2
    
    try:
        conn = psycopg2.connect(
            host=host, 
            database=bd, 
            user=usuario, 
            password=contrasena, 
            port='5432'
        )
        cursor = conn.cursor()
        
        query = """
        SELECT table_schema, table_name
        FROM information_schema.tables
        WHERE table_schema NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
        AND table_type = 'BASE TABLE'
        ORDER BY table_schema, table_name
        """
        
        cursor.execute(query)
        tablas = cursor.fetchall()
        
        cursor.close()
        conn.close()
        
        return tablas
    
    except Exception as e:
        raise Exception(f"Error al obtener tablas: {str(e)}")
