FROM rust:latest
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev wget
RUN wget https://cryptopals.com/static/challenge-data/4.txt -O setcommon/resources/4.txt \ 
    && wget https://cryptopals.com/static/challenge-data/6.txt -O setcommon/resources/6.txt \ 
    && wget https://cryptopals.com/static/challenge-data/7.txt -O setcommon/resources/7.txt \ 
    && wget https://cryptopals.com/static/challenge-data/8.txt -O setcommon/resources/8.txt \
    && wget https://cryptopals.com/static/challenge-data/10.txt -O setcommon/resources/10.txt
RUN cargo install cargo-audit
RUN cd setcommon && cargo build && cargo audit --deny-warnings && cargo test
RUN cd ../set01 && cargo build && cargo audit --deny-warnings && cargo test
RUN cd ../set02 && cargo build && cargo audit --deny-warnings && cargo test

