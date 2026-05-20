# ArgusIDS

ArgusIDS is an Intrusion Detection System designed to monitor network traffic and detect potential security threats. This unstable version builds upon the demo version, introducing new features and improvements.

## Features

- **Network Monitoring:** Continuously monitors network traffic for suspicious activities.
- **Signature-Based Detection:** Uses predefined signatures to identify malicious patterns.
- **Configuration Management:** Easily configurable through a YAML file.
- **Logging Utilities:** Provides detailed logs for monitoring and debugging.

## Prerequisites

Before you begin, ensure that you have the following prerequisites installed:

- [Git](https://git-scm.com/)
- A C compiler (e.g., GCC)
- [CMake](https://cmake.org/) (optional, if using a build system)

## Installation

To install and set up ArgusIDS, follow these steps:

1. **Clone the Repository:**

   ```sh
   git clone https://github.com/yourusername/ArgusIDS.git
   cd ArgusIDS
   ```
   
2. **Build the Project:**

   ```sh
   mkdir build
   cd build
   cmake ..
   make
   sudo make install  # optional
   ```
   
3. **Configure ArgusIDS**:
   Edit the config.yaml file located in the root directory to customize settings according to your needs.
   
5. **Run ArgusIDS:**
   ```sh
     ./argusids
   ```
