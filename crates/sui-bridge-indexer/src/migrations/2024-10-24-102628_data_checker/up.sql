CREATE TABLE data_audits
(
    id                   SERIAL PRIMARY KEY,
    chain_id             INT       NOT NULL,
    status               TEXT      NOT NULL,
    start_time           TIMESTAMP NOT NULL,
    from_nonce           BIGINT    NOT NULL,
    to_nonce             BIGINT    NOT NULL,
    current_nonce        BIGINT,
    end_time             TIMESTAMP,
    incorrect_data_count INT
);