// This is a simplified example demonstrating how to execute shell commands (including iptables) from a Node.js environment.
//  IMPORTANT:  Executing shell commands directly from JavaScript introduces significant security risks, especially if the input (IP addresses) comes from external sources.  You *MUST* sanitize and validate the IP addresses thoroughly to prevent command injection vulnerabilities.

const { exec } = require('child_process');

/**
 * Blocks a suspicious IP address using iptables.
 *
 * @param {string} ipAddress - The IP address to block.  MUST be a valid IP address.
 * @param {number} [ttlSeconds=3600] - Time to live in seconds for the block (default: 1 hour).
 * @returns {Promise<string>} A Promise that resolves with the command output or rejects with an error.
 */
async function blockSuspiciousIP(ipAddress, ttlSeconds = 3600) {
    return new Promise((resolve, reject) => {
        // Input validation and sanitization is *crucial* here.  This is a minimal example.
        if (!isValidIPAddress(ipAddress)) {
            return reject(new Error('Invalid IP address.'));
        }

        // Build the iptables command.  Use single quotes to prevent shell expansion.
        const command = `sudo iptables -A INPUT -s '${ipAddress}' -j DROP; sleep ${ttlSeconds}; sudo iptables -D INPUT -s '${ipAddress}' -j DROP`;


        console.log(`Executing: ${command}`); // Log the command for debugging

        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error blocking IP ${ipAddress}: ${error}`);
                return reject(new Error(`Failed to block IP: ${error.message}`));
            }

            if (stderr) {
                 console.error(`iptables stderr: ${stderr}`); // Log stderr for debugging.
            }

            console.log(`IP ${ipAddress} blocked successfully.`);
            resolve(`IP ${ipAddress} blocked. Command Output: ${stdout}`);
        });
    });
}



/**
 * Validates if the input is a valid IPv4 address using a regular expression.
 *  This function provides basic validation; for more robust validation, consider using a dedicated library.
 *
 * @param {string} ipAddress - The IP address to validate.
 * @returns {boolean} True if the IP address is valid, false otherwise.
 */
function isValidIPAddress(ipAddress) {
  if (typeof ipAddress !== 'string') {
    return false;
  }

  const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = ipAddress.match(ipRegex);

  if (!match) {
    return false;
  }

  // Further validation to ensure each octet is between 0 and 255.
  for (let i = 1; i <= 4; i++) {
    const octet = parseInt(match[i], 10);
    if (isNaN(octet) || octet < 0 || octet > 255) {
      return false;
    }
  }

  return true;
}



// Example usage:
async function main() {
    try {
        const ipToBlock = '192.168.1.100';  // Replace with a dynamic IP.  NEVER hardcode this.
        const ttl = 60; // Block for 60 seconds.  KEEP THIS SHORT FOR TESTING.

        const result = await blockSuspiciousIP(ipToBlock, ttl);
        console.log(result);
    } catch (error) {
        console.error('An error occurred:', error);
    }
}


// Only execute if this script is run directly, not imported as a module.
if (require.main === module) {
    main();
}



//  Important Considerations:

//  1. Security:  This script requires `sudo` to execute iptables commands, meaning the Node.js process running this script will need elevated privileges.  This is a *MAJOR* security risk.  Consider these alternatives:
//      * Use a dedicated service with minimal permissions to manage iptables rules.  The Node.js application can then communicate with this service via a secure API.
//      * Use capabilities (e.g., `cap_net_admin`) instead of `sudo` to grant only the necessary permissions to the Node.js process.  This is a more secure approach.
//      * NEVER directly expose this functionality to external users without extremely robust validation and authorization. Command injection vulnerabilities are a serious threat.
//
//  2. Error Handling: The error handling in this example is basic. Implement robust error handling, logging, and alerting to detect and respond to failures.
//
//  3. IP Address Validation:  The `isValidIPAddress` function provides minimal validation.  Use a more robust library or service for IP address validation and threat intelligence.  Never trust IP addresses from untrusted sources.
//
//  4. Race Conditions:  If multiple instances of this script are running concurrently, they could interfere with each other's iptables rules.  Implement appropriate locking mechanisms to prevent race conditions.
//
//  5. Iptables Complexity:  Iptables rules can become complex and difficult to manage. Consider using a higher-level abstraction layer or a firewall management tool.
//
//  6. IPv6:  This script only handles IPv4 addresses.  Update the `isValidIPAddress` function and the iptables command to support IPv6.
//
//  7. Dynamic Removal: The `sleep` command is a simple way to remove the rule after a period, but it's not ideal. Consider using a more sophisticated method, such as a cron job or a separate process, to manage the lifecycle of the iptables rules. Also make sure to include code to remove the iptable rules in the event of script failure.

//  8. Testing: Thoroughly test this script in a non-production environment before deploying it to production.  Incorrect iptables rules can disrupt network connectivity.