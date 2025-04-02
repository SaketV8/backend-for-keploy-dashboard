<h1 align="center">Backend for Keploy Dashboard</h1>

<div align="center">
<img src="https://img.shields.io/badge/Proof%20of%20Concept-For%20Keploy's%20GSOC%20Proposal-ff5722?style=for-the-badge" alt="Proof of Concept">
<br>
<img src="https://img.shields.io/badge/License-MIT-ed8796.svg?style=for-the-badge" alt="MIT License">
</div>
<br>

> [!IMPORTANT]  
> [🔥 Frontend for this project](https://github.com/saketv8/frontend-for-keploy-dashboard)

<br>

## :book: How to Use / Run on Your Machine

- ### Prerequisites:
    - Install Go (version >= 1.23.3): https://golang.org/dl/
    - Install Goose: https://github.com/pressly/goose

- ### Installation:

    - Install dependencies:
    ```sh
    go mod tidy
    ```
    - Generate the Table and default Data (if required):
    ```sh
    goose -dir=databases/migrations sqlite3 app.db up
    ```

    - Run the API:
    ```sh
    go run main.go
    ```
    > :rocket: You're all set! The Backend API server is now running
    >
    > The server is running on PORT 8080 (or a different port depending on your setup).
    > Please check the terminal logs for the exact port


## :jigsaw: Demonstration Video

https://github.com/user-attachments/assets/b042935a-6503-4681-adc1-0c48cdef3e2d



## :compass: About
This project was created as a Proof of concept (POC) for the [App Dashboard with Metrics and Chart](https://github.com/keploy/gsoc/tree/main/2025#6--app-dashboard-with-metrics-and-chart)

<!-- ![Selection Status](https://img.shields.io/badge/Selection%20Status%20-SELECTED-22c55e?style=for-the-badge) -->

<!-- ![About Author](https://img.shields.io/badge/Created%20by-%20Saket%20Maurya-f5a97f?style=for-the-badge) -->