#!/usr/bin/env python3
"""
explore_indices.py
------------------
Show stats for all indices in a cluster.

Supports:
  • HTTP or HTTPS
  • Basic-auth or API key
  • Custom CA or --insecure
"""

import argparse
import getpass
import sys
from elasticsearch import Elasticsearch
from elastic_transport import ApiError, ConnectionError


def build_client(args: argparse.Namespace) -> Elasticsearch:
    """Create an Elasticsearch client from CLI args."""
    kwargs: dict = {"hosts": [args.url]}

    if args.api_key:
        kwargs["api_key"] = args.api_key
    elif args.user:
        if not args.password:
            args.password = getpass.getpass("Password: ")
        kwargs["basic_auth"] = (args.user, args.password)

    if args.url.startswith("https://"):
        if args.insecure:
            kwargs["verify_certs"] = False
        elif args.ca_cert:
            kwargs["ca_certs"] = args.ca_cert

    return Elasticsearch(**kwargs)


def show_indices(es: Elasticsearch) -> None:
    """Print stats for all indices."""
    try:
        indices = es.cat.indices(format="json", h="index,status,health,docs.count", s="index:asc", v=True)
        if not indices:
            print("No indices found.")
            return

        print(f"{'INDEX':<20} {'STATUS':<8} {'HEALTH':<8} {'DOCS':>12}")
        print("-" * 50)
        for index_info in indices:
            print(
                f"{index_info['index']:<20} "
                f"{index_info['status']:<8} "
                f"{index_info['health']:<8} "
                f"{int(index_info['docs.count']):>12,}"
            )

    except ApiError as e:
        sys.exit(f"Elasticsearch API error: {e}")


def parse_cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Show stats for all indices")
    p.add_argument(
        "--url",
        default="http://localhost:9200",
        help="Cluster URL (default: %(default)s)",
    )
    auth = p.add_mutually_exclusive_group()
    auth.add_argument("--user", help="Username for basic auth")
    auth.add_argument("--api-key", help="API key ID:API_KEY_VALUE")
    p.add_argument("--password", help="Password for basic auth (use prompt if omitted)")
    tls = p.add_argument_group("TLS options (HTTPS only)")
    tls.add_argument("--ca-cert", help="Path to the cluster CA certificate")
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS cert verification (dev only!)",
    )
    return p.parse_args()


def main() -> None:
    args = parse_cli()

    try:
        es = build_client(args)
        es.info()  # force connection now for better error reporting
        show_indices(es)
    except (ConnectionError, ApiError) as exc:
        sys.exit(f"Elasticsearch error: {exc}")


if __name__ == "__main__":
    main() 