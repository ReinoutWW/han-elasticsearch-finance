# HAN-ElasticSearch Demo

This project demonstrates how to use Elasticsearch and Logstash to ingest, process, and analyze financial transaction data. It is designed to showcase a complete data pipeline from raw CSV files into a structured Elasticsearch index.

## Data Source

The data used in this project is based on the "Transactions Fraud Datasets" available on Kaggle.

- **Kaggle Dataset:** [Transactions Fraud Datasets](https://www.kaggle.com/datasets/computingvictor/transactions-fraud-datasets)

## Overview

This setup uses Docker to run a small cluster with Elasticsearch, Kibana, and Logstash.

- **`es-demo/`**: Contains the main project files.
  - **`csv/`**: Holds the raw CSV data (users, cards, transactions).
  - **`pipelines/`**: Contains the Logstash configuration files (`.conf`) for processing the data.
  - **`_index_template/`**: Contains the Elasticsearch index template (`.json`) to define the mappings for the `finance` index.
  - **`docker-compose.yml`**: Defines the services for the Elastic Stack.

## How to Run

1.  Navigate to the `es-demo` directory.
2.  Start the Elasticsearch and Kibana services:
    ```bash
    docker compose up -d elasticsearch kibana
    ```
3.  Upload the index template to Elasticsearch to set up the correct mappings:
    ```bash
    curl.exe -X PUT "http://localhost:9200/_index_template/finance_template" -H "Content-Type: application/json" --data-binary "@_index_template/finance_template.json"
    ```
4.  Run the Logstash pipeline to ingest and process the data:
    ```bash
    docker compose run --rm logstash logstash -f /usr/share/logstash/pipeline/finance.conf
    ```
5.  Once the import is complete, you can explore the data in Kibana at `http://localhost:5601`. 