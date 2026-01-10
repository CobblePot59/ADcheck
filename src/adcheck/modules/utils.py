from adcheck.modules.constants import SENSITIVE_TRUSTEES
from rich.table import Table
import functools


def admin_required(func):
    @functools.wraps(func)
    def wrapper(obj):
        if obj.is_admin:
            return func(obj)
        else:
            pass
    return wrapper

def acl_table(console, json_sd, title=None, well_known_sids=None, sensitive_only=False):
    if title:
        console.print(f"\n[bold yellow]{title}[/bold yellow]")

    if "DACL" not in json_sd or not json_sd.get("DACL"):
        console.print("[dim]No DACL present[/dim]")
        return

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("AceType", style="cyan", no_wrap=True)
    table.add_column("SID", style="green")
    table.add_column("Rights", style="white")
    table.add_column("Flags", style="dim")

    sensitive_found = False

    for ace in json_sd["DACL"]:
        ace_type = ace.get("AceType", "-")
        raw_sid = ace.get("SID", "-")
        rights = "\n".join(ace.get("Rights", [])) if ace.get("Rights") else "-"
        flags = ", ".join(ace.get("AceFlags", [])) if ace.get("AceFlags") else "-"

        sid = well_known_sids.get(raw_sid, raw_sid) if well_known_sids else raw_sid

        is_sensitive = SENSITIVE_TRUSTEES and any(user in sid.lower() for user in SENSITIVE_TRUSTEES)
        
        if sensitive_only and not is_sensitive:
            continue
            
        if is_sensitive:
            sid = f"[bold red]{sid}[/bold red]"
            sensitive_found = True

        table.add_row(ace_type, sid, rights, flags)

    if sensitive_only and not sensitive_found:
        console.print("[dim italic]No rights granted to sensitive trustees[/dim italic]")
    else:
        console.print(table)

    owner_sid = json_sd.get('Owner SID', '-')
    group_sid = json_sd.get('Group SID', '-')
    owner = well_known_sids.get(owner_sid, owner_sid) if well_known_sids else owner_sid
    group = well_known_sids.get(group_sid, group_sid) if well_known_sids else group_sid

    if sensitive_only:
        parts = []
        if SENSITIVE_TRUSTEES and any(user in owner.lower() for user in SENSITIVE_TRUSTEES):
            parts.append(f"[bold cyan]Owner:[/bold cyan] [bold red]{owner}[/bold red]")
        if SENSITIVE_TRUSTEES and any(user in group.lower() for user in SENSITIVE_TRUSTEES):
            parts.append(f"[bold cyan]Group:[/bold cyan] [bold red]{group}[/bold red]")
        
        if parts:
            console.print("   •   ".join(parts))
    else:
        console.print(
            f"[bold cyan]Owner:[/bold cyan] {owner}, "
            f"[bold cyan]Group:[/bold cyan] {group}"
        )