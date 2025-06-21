#!/usr/bin/env python3
"""
explore_data.py
---------------
Show sample documents from an index.

Supports:
  • HTTP or HTTPS
  • Basic-auth or API key
  • Custom CA or --insecure
"""

import argparse
import getpass
import json
import sys
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


def explore_documents(es: Elasticsearch, index: str, size: int) -> None:
    """Fetch and print sample documents."""
    print(f"Showing first {size} documents from index '{index}':")
    try:
        resp = es.search(index=index, query={"match_all": {}}, size=size)
        hits = resp["hits"]["hits"]
        if not hits:
            print("No documents found.")
            return

        for i, hit in enumerate(hits):
            print(f"\n--- Document {i+1} (ID: {hit['_id']}) {'-'*25}")
            # Pretty-print the document source
            print(json.dumps(hit["_source"], indent=2))

    except ApiError as e:
        if e.status_code == 404:
            sys.exit(f"Index '{index}' not found.")
        sys.exit(f"Elasticsearch API error: {e}")


def parse_cli() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Show sample documents from an index")
    p.add_argument("index", nargs="?", default="demo", help="Index name to query (default: %(default)s)")
    p.add_argument(
        "--size",
        type=int,
        default=5,
        help="Number of documents to show (default: %(default)s)",
    )
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
        explore_documents(es, args.index, args.size)
    except (ConnectionError, ApiError) as exc:
        sys.exit(f"Elasticsearch error: {exc}")


if __name__ == "__main__":
    main() 