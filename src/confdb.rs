use rusqlite::{Connection, Result, params};

use crate::{log_error, log_debug, log_info};
use crate::config::LocalConfig;

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
    let query = format!("INSERT INTO global_config (param,value) VALUES(?1,?2)");
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
    let res = conn.execute(&query, params![LocalConfig::USE_DOH_NAME, "yes"]);
    if res.is_err() {
        log_error!("Insert failed\n");
        return Err(res.err().unwrap());
    }
    let res = conn.execute(&query, params![LocalConfig::LOCAL_DNS_NAME, "no"]);
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

pub fn init_conf_db() -> Result<Connection> {
    log_debug!("Start initialization of configuration DB\n");
    let res = Connection::open("config.db");
    if res.is_err() {
        log_error!("Unable to open connection for 'config.db'\n");
        return Err(res.err().unwrap());
    }
    let conn = res.unwrap();
    let res = conn.execute("CREATE TABLE IF NOT EXISTS global_config (
            param TEXT NOT NULL PRIMARY KEY,
            value TEXT NOT NULL
        )",
    []);
    if res.is_err() {
        log_error!("Unable to create global_config table");
        return Err(res.err().unwrap());
    }
    let res = is_table_empty(&conn, "global_config");
    if res.is_err() {
        log_error!("Something went wrong\n");
        return Err(res.err().unwrap());
    }
    if res.unwrap() {
        log_info!("Table 'global_config' is empty\n");
        let res = fill_def_global_config(&conn);
        if res.is_err() {
            log_error!("Unable to insert default values to global_config");
            return Err(res.err().unwrap());
        }
    }

    log_debug!("Done initialization of configuration DB\n");

    Ok(conn)
}

pub fn get_global_config_value(conn: &Connection, param: &String, value: &mut String) -> bool {
    let res = conn.query_row("SELECT value FROM global_config WHERE param=?1", 
        params![param],
        |row| row.get::<_, String>(0));

    if res.is_err() {
        log_error!("Unable to read {} paramerer\n", param);
        return false;
    }
    *value = res.unwrap();

    return true;
}

pub fn update_global_config_value(conn: &Connection, param: &String, value: &String) -> bool {
    let res = conn.execute("UPDATE global_config SET value=?1 WHERE param=?2",
        params![value, param]);
    if res.is_err() {
        log_error!("Unable to update parameter: {}\n", param);
        return false;
    }

    return true;
}
