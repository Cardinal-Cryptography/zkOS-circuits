use std::fs::File;

use prettytable::{Cell, Table};

pub fn deposit_field_names() -> &'static str {
    "id_hiding, amount, new_note, new_note_index"
}

pub fn deposit_table() -> Table {
    table(deposit_field_names())
}

pub fn save_deposit_table(table: Table) {
    println!("\n\nDEPOSIT_NATIVE\n\n");
    table.printstd();
    let out = File::create("deposit_native.csv").unwrap();
    table.to_csv(out).unwrap();
}

pub fn withdraw_field_names() -> &'static str {
    "id_hiding, amount, \"to\", new_note, new_note_index, relayer_address, fee"
}

pub fn withdraw_table() -> Table {
    table(withdraw_field_names())
}

pub fn save_withdraw_table(table: Table) {
    println!("\n\nWITHDRAW_NATIVE\n\n");
    table.printstd();
    let out = File::create("withdraw_native.csv").unwrap();
    table.to_csv(out).unwrap();
}

fn table(field_names: &'static str) -> Table {
    let mut table = Table::new();
    table.add_row(field_names.split(", ").map(Cell::new).collect());
    table
}
