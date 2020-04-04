FROM rust:latest
COPY . .
RUN apt-get update && apt-get install -y pkg-config libssl-dev wget
RUN wget https://cryptopals.com/static/challenge-data/4.txt -O resources/4.txt \ 
    && wget https://cryptopals.com/static/challenge-data/6.txt -O resources/6.txt \ 
    && wget https://cryptopals.com/static/challenge-data/7.txt -O resources/7.txt \ 
    && wget https://cryptopals.com/static/challenge-data/8.txt -O resources/8.txt
RUN cargo install cargo-audit
RUN cargo build
RUN cargo audit --deny-warnings
CMD [ "cargo", "test" ]