use crate::error::{CliError, Result};
use clap::ValueEnum;
use serde_json::Value;
use std::io::{self, IsTerminal};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
}

pub fn effective_format(requested: Option<OutputFormat>) -> OutputFormat {
    requested.unwrap_or_else(|| {
        if io::stdout().is_terminal() {
            OutputFormat::Table
        } else {
            OutputFormat::Json
        }
    })
}

pub fn render(value: &Value, format: OutputFormat) -> Result<()> {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(value)
                .map_err(|error| CliError::Api(format!("cannot encode response: {error}")))?
        ),
        OutputFormat::Table => render_table(value),
    }
    Ok(())
}

fn render_table(value: &Value) {
    match value {
        Value::Array(rows) if rows.is_empty() => println!("No results."),
        Value::Array(rows) if rows.iter().all(Value::is_object) => {
            let columns = columns(rows);
            println!("{}", columns.join("\t"));
            for row in rows {
                let values = columns
                    .iter()
                    .map(|column| cell(row.get(column)))
                    .collect::<Vec<_>>();
                println!("{}", values.join("\t"));
            }
        }
        Value::Object(fields) => {
            for (key, value) in fields {
                println!("{key}\t{}", cell(Some(value)));
            }
        }
        _ => println!("{}", cell(Some(value))),
    }
}

fn columns(rows: &[Value]) -> Vec<&str> {
    let preferred = [
        "client_id",
        "id",
        "name",
        "display_name",
        "email",
        "role",
        "status",
        "provider_type",
        "trigger",
        "enabled",
        "event_type",
        "actor_id",
        "target_id",
        "timestamp",
        "expires_at",
        "superadmin",
        "first_party",
    ];
    let mut result = Vec::new();
    for name in preferred {
        if rows.iter().any(|row| row.get(name).is_some()) {
            result.push(name);
        }
    }
    if result.is_empty() {
        for row in rows {
            for key in row.as_object().into_iter().flat_map(|object| object.keys()) {
                if !result.contains(&key.as_str()) {
                    result.push(key);
                }
                if result.len() == 5 {
                    return result;
                }
            }
        }
    }
    result
}

fn cell(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "-".into(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Array(values)) if values.iter().all(|value| value.is_string()) => values
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        Some(value) => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrays_of_strings_are_compact_cells() {
        assert_eq!(
            cell(Some(&serde_json::json!(["openid", "email"]))),
            "openid,email"
        );
    }
}
