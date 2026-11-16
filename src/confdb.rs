use rusqlite::{Connection, Result, params};
use std::net::Ipv4Addr;

use crate::{log_error, log_debug, log_info};
use crate::config::LocalConfig;

const SQLITE_DB_FILE: &str = "config.db";
const SQLITE_TABLE_CONFIG: &str = "global_config";
const SQLITE_TABLE_NAMES: &str = "local_names";
const SQLITE_TABLE_FILTER: &str = "filter";

pub struct LocalName {
    pub name: String,
    pub address: String
}

fn is_table_empty(conn: &Connection, table_name: &str) -> Result<bool> {
    let query = format!("SELECT 1 FROM {} LIMIT 1", table_name);
    let res =  conn.prepare(&query);
    if res.is_err() {
        return Err(res.err().unwrap());
    }
    let mut stmt = res.unwrap();
    let res = stmt.exists([]);
    if res.is_err() {
        return Err(res.err().unwrap());
    }
    Ok(!res.unwrap())
}

fn fill_def_global_config(conn: &Connection) -> Result<()> {
    let query = format!("INSERT INTO {} (param,value) VALUES(?1,?2)", SQLITE_TABLE_CONFIG);
    let res = conn.execute(&query, params![LocalConfig::LISTEN_ADDR_NAME, "0.0.0.0"]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }
    let res = conn.execute(&query, params![LocalConfig::LISTEN_PORT_NAME, "53"]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }
    let res = conn.execute(&query, params![LocalConfig::DNS_SERVER_NAME, "1.1.1.1"]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }
    let res = conn.execute(&query, params![LocalConfig::USE_DOH_NAME, LocalConfig::YES_VALUE]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }
    let res = conn.execute(&query, params![LocalConfig::LOCAL_DNS_NAME, LocalConfig::NO_VALUE]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }
    let res = conn.execute(&query, params![LocalConfig::LOCAL_DOMAIN_NAME, "home"]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }

    Ok(())
}

pub fn sqldb_init_conf_db() -> Result<Connection> {
    log_debug!("Start initialization of configuration DB\n");
    let res = Connection::open(SQLITE_DB_FILE);
    if res.is_err() {
        log_error!("Unable to open connection for 'config.db'\n");
        return Err(res.err().unwrap());
    }
    let conn = res.unwrap();
    let sql = format!("CREATE TABLE IF NOT EXISTS {} (
            param TEXT NOT NULL PRIMARY KEY,
            value TEXT NOT NULL
        )", SQLITE_TABLE_CONFIG);
    let res = conn.execute(&sql, []);
    if res.is_err() {
        log_error!("Unable to create {} table\n", SQLITE_TABLE_CONFIG);
        return Err(res.err().unwrap());
    }
    let res = is_table_empty(&conn, SQLITE_TABLE_CONFIG);
    if res.is_err() {
        log_error!("Something went wrong\n");
        return Err(res.err().unwrap());
    }
    if res.unwrap() {
        log_info!("Table '{}' is empty\n", SQLITE_TABLE_CONFIG);
        let res = fill_def_global_config(&conn);
        if res.is_err() {
            log_error!("Unable to insert default values to {}\n", SQLITE_TABLE_CONFIG);
            return Err(res.err().unwrap());
        }
    }
    let sql = format!("CREATE TABLE IF NOT EXISTS {} (
            name TEXT NOT NULL PRIMARY KEY,
            address TEXT NOT NULL
        )", SQLITE_TABLE_NAMES);
    let res = conn.execute(&sql, []);
    if res.is_err() {
        let e = res.err().unwrap();
        log_error!("Unable to create {} table. Error: {}\n", SQLITE_TABLE_NAMES, e);
        return Err(e);
    }
    let sql = format!("CREATE TABLE IF NOT EXISTS {} (
            name TEXT NOT NULL PRIMARY KEY,
            reject_count INTEGER NOT NULL DEFAULT 0,
            enable INTEGER NOT NULL DEFAULT 0 CHECK (enable IN (0, 1)),
            filter_type INTEGER NOT NULL DEFAULT 0
        )", SQLITE_TABLE_FILTER);
    let res = conn.execute(&sql, []);
    if res.is_err() {
        let e = res.err().unwrap();
        log_error!("Unable to create {} table. Error: {}\n", SQLITE_TABLE_NAMES, e);
        return Err(e);
    }

    log_debug!("Done initialization of configuration DB\n");

    Ok(conn)
}

pub fn sqldb_get_global_config_value(conn: &Connection, param: &String, value: &mut String) -> bool {
    let sql = format!("SELECT value FROM {} WHERE param=?1", SQLITE_TABLE_CONFIG);
    let res = conn.query_row(&sql, params![param],
        |row| row.get::<_, String>(0));

    if res.is_err() {
        log_error!("Unable to read {} paramerer\n", param);
        return false;
    }
    *value = res.unwrap();

    return true;
}

pub fn sqldb_update_global_config_value(conn: &Connection, param: &String, value: &String) -> bool {
    let sql = format!("UPDATE {} SET value=?1 WHERE param=?2", SQLITE_TABLE_CONFIG);
    let res = conn.execute(&sql, params![value, param]);
    if res.is_err() {
        log_error!("Unable to update parameter: {}\n", param);
        return false;
    }

    return true;
}

pub fn sqldb_get_ip_for_local_name(conn: &Connection, name: &String) -> Result<Ipv4Addr> {
    let sql = format!("SELECT address FROM {} WHERE name=?1", SQLITE_TABLE_NAMES);
    let res = conn.query_row(&sql, params![name],
        |row| row.get::<_, String>(0));
    if res.is_err() {
        return Err(res.err().unwrap());        
    }
    let address = res.unwrap();
    let res = address.parse::<Ipv4Addr>();
    if res.is_err() {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let addr = res.unwrap();

    return Ok(addr);
}

pub fn sqldb_remove_local_name(conn: &Connection, name: &String) -> Result<()> {
    let sql = format!("DELETE FROM {} WHERE name=?1", SQLITE_TABLE_NAMES);
    let res = conn.execute(&sql, params![name]);
    if res.is_err() {
        return Err(res.err().unwrap());
    }

    Ok(())
}

pub fn sqldb_insert_local_name(conn: &Connection, name: &String, str_addr: &String) -> Result<()> {
    let sql = format!("INSERT INTO {} (name,address) VALUES (?1,?2)", SQLITE_TABLE_NAMES);
    let res = conn.execute(&sql, params![name, str_addr]);
    if res.is_err() {
        return Err(res.err().unwrap());
    }

    Ok(())
}

pub fn sqldb_get_local_names(conn: &Connection) -> Result<Vec<LocalName>> {
    let sql = format!("SELECT name, address FROM {}", SQLITE_TABLE_NAMES);
    let res = conn.prepare(&sql);
    if res.is_err() {
        return Err(res.err().unwrap());
    }
    let mut stmt = res.unwrap();
    let res = stmt.query_map([], |row| {
        Ok(LocalName {
            name: row.get(0).unwrap(),
            address: row.get(1).unwrap()
        })
    });
    if res.is_err() {
        return Err(res.err().unwrap());
    }
    let row_iter = res.unwrap();
    let mut local_names: Vec<LocalName> = vec![];
    for names_result in row_iter {
        local_names.push(names_result.unwrap());
    }

    Ok(local_names)
}

pub fn sqldb_update_local_name(conn: &Connection, name: &String, str_addr: &String) -> Result<()> {
    let sql = format!("UPDATE {} SET address=?1 WHERE name=?2", SQLITE_TABLE_NAMES);
    let res = conn.execute(&sql, params![str_addr, name]);
    if res.is_err() {
        return Err(res.err().unwrap());
    }

    Ok(())
}

