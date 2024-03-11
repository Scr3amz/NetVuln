## Introdution
This project is a gRPC service built in the Golang programming language, providing a wrapper around the network scanning tool Nmap. With this service, you can perform network scans and discover vulnerabilities in systems.

## Installation

Before you begin, ensure you have Go and Nmap installed. Then follow these steps:

1. Clone the repository:

   git clone https://github.com/Scr3amz/NetVuln.git

2. Navigate to the project directory:

    cd NetVuln
    
3. Install dependencies:

    go get -u

4. Build the project:

    make build

## Usage

1. Start the gRPC server:
    make run

2. Now you can use client libraries to connect to the gRPC server and make scan requests.