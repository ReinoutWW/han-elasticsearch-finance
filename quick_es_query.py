#!/usr/bin/env python3
"""
flex_es_query.py
----------------
Query an Elasticsearch index and print record count + elapsed time.

Supports:
  • HTTP or HTTPS
  • Basic-auth or API key
  • Custom CA or --insecure
Install:
    pip install elasticsearch>=8.13.0
"""

import argparse
import getpass
import sys
import time
from elasticsearch import Elasticsearch
from elastic_transport import ApiError, ConnectionError


def build_client(args: argparse.Namespace) -> Elasticsearch:
    """Create an Elasticsearch client from CLI args."""
    # Build kwargs incrementally
    kwargs: dict = {"hosts": [args.url]}

    # ---- Auth --------------------------------------------------------------
    if args.api_key:
        kwargs["api_key"] = args.api_key
    elif args.user:
        if not args.password:
            args.password = getpass.getpass("Password: ")
        kwargs["basic_auth"] = (args.user, args.password)

    # ---- TLS ---------------------------------------------------------------
    if args.url.startswith("https://"):
        if args.insecure:
            kwargs["verify_certs"] = False
        elif args.ca_cert:
            kwargs["ca_certs"] = args.ca_cert  # PEM file produced by Elasticsearch
        # Otherwise: default cert verification

    return Elasticsearch(**kwargs)


def query_index(es: Elasticsearch, index: str) -> None:
    """Run a match_all search and print metrics."""
    body = {"match_all": {}}
    t0 = time.perf_counter()
    rsp = es.search(index=index, query=body, size=0)
    elapsed = (time.perf_counter() - t0) * 1000

    total = rsp["hits"]["total"]
    total = total["value"] if isinstance(total, dict) else total

    print(f"Index       : {index}")
    print(f"Record count: {total:,}")
    print(f"Elapsed time: {elapsed:.2f} ms")


def parse_cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Quick Elasticsearch count query")
    p.add_argument("index", help="Index name to query")
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
        query_index(es, args.index)
    except (ConnectionError, ApiError) as exc:
        sys.exit(f"Elasticsearch error: {exc}")


if __name__ == "__main__":
    main()
