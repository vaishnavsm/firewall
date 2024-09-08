mod build;
mod build_firewall;
mod build_probe_entry;
mod build_ebpf_common;
mod run;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildProbeEntry(build_ebpf_common::Options),
    BuildFirewall(build_ebpf_common::Options),
    Build(build::Options),
    Run(run::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildFirewall(opts) => build_firewall::build_firewall(opts),
        BuildProbeEntry(opts) => build_probe_entry::build_probe_entry(opts),
        Run(opts) => run::run(opts),
        Build(opts) => build::build(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
