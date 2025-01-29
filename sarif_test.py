from sarif_cmp import sarif_to_df, sarif_to_rule_map
from pathlib import Path
import json

def test_sarif_to_rule_map_bandit():
    bandit_rules = [
        {
              "id": "B324",
              "name": "hashlib",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-327"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/plugins/b324_hashlib.html"
            },
            {
              "id": "B608",
              "name": "hardcoded_sql_expressions",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-89"
                ],
                "precision": "low"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/plugins/b608_hardcoded_sql_expressions.html"
            },
            {
              "id": "B101",
              "name": "assert_used",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-703"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/plugins/b101_assert_used.html"
            },
            {
              "id": "B104",
              "name": "hardcoded_bind_all_interfaces",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-605"
                ],
                "precision": "medium"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/plugins/b104_hardcoded_bind_all_interfaces.html"
            },
            {
              "id": "B305",
              "name": "blacklist",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-327"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/blacklists/blacklist_calls.html#b304-b305-ciphers-and-modes"
            },
            {
              "id": "B413",
              "name": "blacklist",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-327"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/blacklists/blacklist_imports.html#b413-import-pycrypto"
            },
            {
              "id": "B304",
              "name": "blacklist",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-327"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/blacklists/blacklist_calls.html#b304-b305-ciphers-and-modes"
            },
            {
              "id": "B303",
              "name": "blacklist",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-327"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/blacklists/blacklist_calls.html#b303-md5"
            },
            {
              "id": "B403",
              "name": "blacklist",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-502"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/blacklists/blacklist_imports.html#b403-import-pickle"
            },
            {
              "id": "B301",
              "name": "blacklist",
              "properties": {
                "tags": [
                  "security",
                  "external/cwe/cwe-502"
                ],
                "precision": "high"
              },
              "helpUri": "https://bandit.readthedocs.io/en/1.8.2/blacklists/blacklist_calls.html#b301-pickle"
            }
    ]
    expected = {
        "B324": {"CWE-327"},
        "B608": {"CWE-89"},
        "B101": {"CWE-703"},
        "B104": {"CWE-605"},
        "B305": {"CWE-327"},
        "B413": {"CWE-327"},
        "B304": {"CWE-327"},
        "B303": {"CWE-327"},
        "B403": {"CWE-502"},
        "B301": {"CWE-502"}
    }
    actual = sarif_to_rule_map(bandit_rules)
    assert len(actual) == len(expected), f"Expected: {len(expected)}; Got: {len(actual)}"
    for k in actual.keys():
        assert expected[k] == actual[k], f"Expected: {expected[k]}; Got: {actual[k]}"
            

def test_sarif_to_rule_map_spotbugs():
    spotbugs_rules = [
        {
            "id": "CRLF_INJECTION_LOGS",
            "shortDescription": {
                "text": "Potential CRLF Injection for logs."
            },
            "messageStrings": {
                "default": {
                    "text": "This use of {0} might be used to include CRLF characters into log messages."
                }
            },
            "helpUri": "https://find-sec-bugs.github.io/bugs.htm#CRLF_INJECTION_LOGS",
            "properties": {
                "tags": [
                    "SECURITY"
                ]
            },
            "relationships": [
                {
                    "target": {
                        "id": "117",
                        "guid": "e4360770-eb15-55cf-8880-7051868a1961",
                        "toolComponent": {
                            "name": "CWE",
                            "guid": "b8c54a32-de19-51d2-9a08-f0abfbaa7310"
                        }
                    },
                    "kinds": [
                        "superset"
                    ]
                }
            ]
        },
        {
            "id": "ENTITY_LEAK",
            "shortDescription": {
                "text": "Unexpected property leak."
            },
            "messageStrings": {
                "default": {
                    "text": "Unexpected property could be leaked because a persistence class is directly exposed to the client."
                }
            },
            "helpUri": "https://find-sec-bugs.github.io/bugs.htm#ENTITY_LEAK",
            "properties": {
                "tags": [
                    "SECURITY"
                ]
            },
            "relationships": [
                {
                    "target": {
                        "id": "212",
                        "guid": "979f6dec-8e20-56ce-9982-ce9e75d3c245",
                        "toolComponent": {
                            "name": "CWE",
                            "guid": "b8c54a32-de19-51d2-9a08-f0abfbaa7310"
                        }
                    },
                    "kinds": [
                        "superset"
                    ]
                }
            ]
        },
        {
            "id": "ENTITY_MASS_ASSIGNMENT",
            "shortDescription": {
                "text": "Mass assignment."
            },
            "messageStrings": {
                "default": {
                    "text": "Persistent objects as MVC parameter could allow attacker to set fields that the developer never intended to be set via request parameters."
                }
            },
            "helpUri": "https://find-sec-bugs.github.io/bugs.htm#ENTITY_MASS_ASSIGNMENT",
            "properties": {
                "tags": [
                    "SECURITY"
                ]
            },
            "relationships": [
                {
                    "target": {
                        "id": "915",
                        "guid": "ec76b642-6a30-570d-93b4-289a1b26ca78",
                        "toolComponent": {
                            "name": "CWE",
                            "guid": "b8c54a32-de19-51d2-9a08-f0abfbaa7310"
                        }
                    },
                    "kinds": [
                        "superset"
                    ]
                }
            ]
        },
        {
            "id": "HTTPONLY_COOKIE",
            "shortDescription": {
                "text": "Cookie without the HttpOnly flag."
            },
            "messageStrings": {
                "default": {
                    "text": "Cookie without the HttpOnly flag could be read by a malicious script in the browser."
                }
            },
            "helpUri": "https://find-sec-bugs.github.io/bugs.htm#HTTPONLY_COOKIE",
            "properties": {
                "tags": [
                    "SECURITY"
                ]
            },
            "relationships": [
                {
                    "target": {
                        "id": "1004",
                        "guid": "0783f9dc-1212-5d10-894d-057c797ba987",
                        "toolComponent": {
                            "name": "CWE",
                            "guid": "b8c54a32-de19-51d2-9a08-f0abfbaa7310"
                        }
                    },
                    "kinds": [
                        "superset"
                    ]
                }
            ]
        },
        {
            "id": "INSECURE_COOKIE",
            "shortDescription": {
                "text": "Cookie without the secure flag."
            },
            "messageStrings": {
                "default": {
                    "text": "Cookie without the secure flag could be sent in clear text if a HTTP URL is visited."
                }
            },
            "helpUri": "https://find-sec-bugs.github.io/bugs.htm#INSECURE_COOKIE",
            "properties": {
                "tags": [
                    "SECURITY"
                ]
            },
            "relationships": [
                {
                    "target": {
                        "id": "614",
                        "guid": "06a50c3b-db90-53ee-9dcd-bdf22e7b9a5a",
                        "toolComponent": {
                            "name": "CWE",
                            "guid": "b8c54a32-de19-51d2-9a08-f0abfbaa7310"
                        }
                    },
                    "kinds": [
                        "superset"
                    ]
                }
            ]
        },
        {
            "id": "SIC_INNER_SHOULD_BE_STATIC",
            "shortDescription": {
                "text": "Should be a static inner class."
            },
            "messageStrings": {
                "default": {
                    "text": "Should {0} be a _static_ inner class?."
                }
            },
            "helpUri": "https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html#SIC_INNER_SHOULD_BE_STATIC",
            "properties": {
                "tags": [
                    "PERFORMANCE"
                ]
            }
        }
    ]
    expected = {
        "CRLF_INJECTION_LOGS": {"CWE-117"},
        "ENTITY_LEAK" : {"CWE-212"},
        "ENTITY_MASS_ASSIGNMENT": {"CWE-915"},
        "HTTPONLY_COOKIE": {"CWE-1004"},
        "INSECURE_COOKIE": {"CWE-614"}
    }
    actual = sarif_to_rule_map(spotbugs_rules)
    # for k,v in actual.items():
    #     print(f"{k}: {v}")
    assert len(actual) == len(expected), f"Expected: {len(expected)}; Got: {len(actual)}"
    for k in actual.keys():
        assert expected[k] == actual[k], f"Expected: {expected[k]}; Got: {actual[k]}"

def test_sarif_to_rule_map_fortify():
    fod_rules = [
        {
            "id": "11BF839E-A56A-4CA7-BFD2-9AC137C69F060",
            "shortDescription": {
                "text": "Command Injection"
            },
            "fullDescription": {
                "text": "## Command Injection\n\nExecuting commands from an untrusted source or in an untrusted environment can cause an application to execute malicious commands on behalf of an attacker.\n"
            },
            "help": {
                "text": "Command injection vulnerabilities take two forms:\n\n- An attacker can change the command that the program executes: the attacker explicitly controls what the command is.\n\n- An attacker can change the environment in which the command executes: the attacker implicitly controls what the command means.\n\nIn this case, we are primarily concerned with the first scenario, the possibility that an attacker may be able to control the command that is executed. Command injection vulnerabilities of this type occur when:\n\n1. Data enters the application from an untrusted source.\n\n\n2. The data is used as or as part of a string representing a command that is executed by the application.\n\n3. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.\n\nExample 1: The following code from a system utility uses the system property `APPHOME` to determine the directory in which it is installed and then executes an initialization script based on a relative path from the specified directory.\n\n\n\n    ...\n    home = os.getenv('APPHOME')\n    cmd = home.join(INITCMD)\n    os.system(cmd);\n    ...\n\n\nThe code in `Example 1` allows an attacker to execute arbitrary commands with the elevated privilege of the application by modifying the system property `APPHOME` to point to a different path containing a malicious version of `INITCMD`. Because the program does not validate the value read from the environment, if an attacker can control the value of the system property `APPHOME`, then they can fool the application into running malicious code and take control of the system.\n\nExample 2: The following code is from an administrative web application designed to allow users to kick off a backup of an Oracle database using a batch-file wrapper around the `rman` utility and then run a `cleanup.bat` script to delete some temporary files. The script `rmanDB.bat` accepts a single command line parameter, which specifies the type of backup to perform. Because access to the database is restricted, the application runs the backup as a privileged user.\n\n\n\n    ...\n    btype = req.field('backuptype')\n    cmd = \"cmd.exe /K \\\"c:\\\\util\\\\rmanDB.bat \" + btype + \"&&c:\\\\util\\\\cleanup.bat\\\"\"\n    os.system(cmd);\n    ...\n\n\nThe problem here is that the program does not do any validation on the `backuptype` parameter read from the user. Typically the `Runtime.exec()` function will not execute multiple commands, but in this case the program first runs the `cmd.exe` shell in order to run multiple commands with a single call to `Runtime.exec()`. After the shell is invoked, it will allow for the execution of multiple commands separated by two ampersands. If an attacker passes a string of the form `\"&amp;&amp; del c:\\\\dbms\\\\*.*\"`, then the application will execute this command along with the others specified by the program. Because of the nature of the application, it runs with the privileges necessary to interact with the database, which means whatever command the attacker injects will run with those privileges as well.\n\nExample 3: The following code is from a web application that provides an interface through which users can update their password on the system. Part of the process for updating passwords in certain network environments is to run a `make` command in the `/var/yp` directory.\n\n\n\n    ...\n    result = os.system(\"make\");\n    ...\n\n\nThe problem here is that the program does not specify an absolute path for make and fails to clean its environment prior to executing the call to `os.system()`. If an attacker can modify the `$PATH` variable to point to a malicious binary called `make` and cause the program to be executed in their environment, then the malicious binary will be loaded instead of the one intended. Because of the nature of the application, it runs with the privileges necessary to perform system operations, which means the attacker's `make` will now be run with these privileges, possibly giving the attacker complete control of the system.\n\n## Recommendations\n\nDo not allow users to have direct control over the commands executed by the program. In cases where user input must affect the command to be run, use the input only to make a selection from a predetermined set of safe commands. If the input appears to be malicious, the value passed to the command execution function should either default to some safe selection from this set or the program should decline to execute any command at all.\n\nIn cases where user input must be used as an argument to a command executed by the program, this approach often becomes impractical because the set of legitimate argument values is too large or too hard to keep track of. Developers often fall back on implementing a deny list in these situations. A deny list is used to selectively reject or escape potentially dangerous characters before using the input. Any list of unsafe characters is likely to be incomplete and will be heavily dependent on the system where the commands are executed. A better approach is to create a list of characters that are permitted to appear in the input and accept input composed exclusively of characters in the approved set.\n\nAn attacker may indirectly control commands executed by a program by modifying the environment in which they are executed. The environment should not be trusted and precautions should be taken to prevent an attacker from using some manipulation of the environment to perform an attack. Whenever possible, commands should be controlled by the application and executed using an absolute path. In cases where the path is not known at compile time, such as for cross-platform applications, an absolute path should be constructed from trusted values during execution. Command values and paths read from configuration files or the environment should be sanity-checked against a set of invariants that define valid values.\n\nOther checks can sometimes be performed to detect if these sources may have been tampered with. For example, if a configuration file is world-writable, the program might refuse to run. In cases where information about the binary to be executed is known in advance, the program may perform checks to verify the identity of the binary. If a binary should always be owned by a particular user or have a particular set of access permissions assigned to it, these properties can be verified programmatically before the binary is executed.\n\nAlthough it may be impossible to completely protect a program from an imaginative attacker bent on controlling the commands the program executes, be sure to apply the principle of least privilege wherever the program executes an external command: do not hold privileges that are not essential to the execution of the command.\n\n## Tips\n\nNot available\n\n## References\n\n1. CWE ID 77, CWE ID 78, Standards Mapping - Common Weakness Enumeration\n2. [11] CWE ID 078, Standards Mapping - Common Weakness Enumeration Top 25 2019\n3. [10] CWE ID 078, Standards Mapping - Common Weakness Enumeration Top 25 2020\n4. [5] CWE ID 078, [25] CWE ID 077, Standards Mapping - Common Weakness Enumeration Top 25 2021\n5. CCI-001310, CCI-002754, Standards Mapping - DISA Control Correlation Identifier Version 2\n6. SI, Standards Mapping - FIPS200\n7. Indirect Access to Sensitive Data, Standards Mapping - General Data Protection Regulation\n8. Rule 1.3, Standards Mapping - MISRA C 2012\n9. Rule 0-3-1, Standards Mapping - MISRA C++ 2008\n10. SI-10 Information Input Validation (P1), Standards Mapping - NIST Special Publication 800-53 Revision 4\n11. SI-10 Information Input Validation, Standards Mapping - NIST Special Publication 800-53 Revision 5\n12. 5.2.2 Sanitization and Sandboxing Requirements (L1 L2 L3), 5.2.3 Sanitization and Sandboxing Requirements (L1 L2 L3), 5.2.5 Sanitization and Sandboxing Requirements (L1 L2 L3), 5.2.8 Sanitization and Sandboxing Requirements (L1 L2 L3), 5.3.6 Output Encoding and Injection Prevention Requirements (L1 L2 L3), 5.3.8 Output Encoding and Injection Prevention Requirements (L1 L2 L3), 10.3.2 Deployed Application Integrity Controls (L1 L2 L3), 12.3.2 File Execution Requirements (L1 L2 L3), 12.3.5 File Execution Requirements (L1 L2 L3), Standards Mapping - OWASP Application Security Verification Standard 4.0\n13. MASVS-CODE-4, Standards Mapping - OWASP Mobile Application Security Verification Standard 2.0\n14. M7 Client Side Injection, Standards Mapping - OWASP Mobile Top 10 Risks 2014\n15. M4 Insufficient Input/Output Validation, Standards Mapping - OWASP Mobile Top 10 Risks 2023\n16. M4 Insufficient Input/Output Validation, Standards Mapping - OWASP Mobile Top 10 Risks 2024\n17. A6 Injection Flaws, Standards Mapping - OWASP Top 10 2004\n18. A2 Injection Flaws, Standards Mapping - OWASP Top 10 2007\n19. A1 Injection, Standards Mapping - OWASP Top 10 2010\n20. A1 Injection, Standards Mapping - OWASP Top 10 2013\n21. A1 Injection, Standards Mapping - OWASP Top 10 2017\n22. A03 Injection, Standards Mapping - OWASP Top 10 2021\n23. Requirement 6.5.6, Standards Mapping - Payment Card Industry Data Security Standard Version 1.1\n24. Requirement 6.3.1.1, Requirement 6.5.2, Standards Mapping - Payment Card Industry Data Security Standard Version 1.2\n25. Requirement 6.5.1, Standards Mapping - Payment Card Industry Data Security Standard Version 2.0\n26. Requirement 6.5.1, Standards Mapping - Payment Card Industry Data Security Standard Version 3.0\n27. Requirement 6.5.1, Standards Mapping - Payment Card Industry Data Security Standard Version 3.1\n28. Requirement 6.5.1, Standards Mapping - Payment Card Industry Data Security Standard Version 3.2\n29. Requirement 6.5.1, Standards Mapping - Payment Card Industry Data Security Standard Version 3.2.1\n30. Requirement 6.2.4, Standards Mapping - Payment Card Industry Data Security Standard Version 4.0\n31. Control Objective 4.2 - Critical Asset Protection, Standards Mapping - Payment Card Industry Software Security Framework 1.0\n32. Control Objective 4.2 - Critical Asset Protection, Control Objective B.3.1 - Terminal Software Attack Mitigation, Control Objective B.3.1.1 - Terminal Software Attack Mitigation, Standards Mapping - Payment Card Industry Software Security Framework 1.1\n33. Control Objective 4.2 - Critical Asset Protection, Control Objective B.3.1 - Terminal Software Attack Mitigation, Control Objective B.3.1.1 - Terminal Software Attack Mitigation, Control Objective C.3.2 - Web Software Attack Mitigation, Standards Mapping - Payment Card Industry Software Security Framework 1.2\n34. Insecure Interaction - CWE ID 078, Standards Mapping - SANS Top 25 2009\n35. Insecure Interaction - CWE ID 078, Standards Mapping - SANS Top 25 2010\n36. Insecure Interaction - CWE ID 078, Standards Mapping - SANS Top 25 2011\n37. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.1\n38. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.10\n39. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.4\n40. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.5\n41. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.6\n42. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.7\n43. APP3510 CAT I, APP3570 CAT I, Standards Mapping - Security Technical Implementation Guide Version 3.9\n44. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.1\n45. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.10\n46. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.11\n47. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.2\n48. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.3\n49. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.4\n50. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.5\n51. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.6\n52. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.7\n53. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.8\n54. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 4.9\n55. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 5.1\n56. APSC-DV-002510 CAT I, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 5.2\n57. APSC-DV-002510 CAT I, APSC-DV-002530 CAT II, APSC-DV-002560 CAT I, Standards Mapping - Security Technical Implementation Guide Version 5.3\n58. OS Commanding, Standards Mapping - Web Application Security Consortium 24 + 2\n59. OS Commanding (WASC-31), Standards Mapping - Web Application Security Consortium Version 2.00\n\n\nCopyright (c) 2025 Open Text\n"
            }
        },
        {
            "id": "28AC7755-F497-4170-A394-8404B81A92A9",
            "shortDescription": {
            "text": "Encoding Confusion: BiDi Control Characters"
            },
            "fullDescription": {
            "text": "## Encoding Confusion: BiDi Control Characters\n\nBidirectional control characters in source code can lead to trojan source attacks.\n"
            },
            "help": {
            "text": "Source code that contains Unicode bidirectional override control characters can be a sign of an insider threat attack. Such an attack can be leveraged through the supply chain for programming languages such as C, C++, C#, Go, Java, JavaScript, Python, and Rust. Several variant attacks are already published by Nicholas Boucher and Ross Anderson, including the following: Early Returns, Commenting-Out, and Stretched Strings.\n\nExample 1: The following code exhibits a control character, present in a C source code file, which leads to an Early Return attack:\n\n\n    #include <stdio.h>\n    \n    int main() {\n    /* Nothing to see here; newline RLI /*/ return 0 ;\n    printf(\"Do we get here?\n\");\n    return 0;\n    }\n\nThe Right-to-Left Isolate (RLI) Unicode bidirectional control character, in `Example 1`, causes the code to be viewed as the following:\n\n\n    #include <stdio.h>\n    \n    int main() {\n    /* Nothing to see here; newline; return 0 /*/\n    printf(\"Do we get here?\n\");\n    return 0;\n    }\n\nOf particular note is that a developer who performs a code review, in a vulnerable editor/viewer, would not visibly see what a vulnerable compiler will process. Specifically, the early return statement that modifies the program flow.\n\n## Recommendations\n\nFortify recommends the following:\n(1) Identify all Unicode bidirectional (BiDi) control characters in source code files within a software supply chain.\n(2) Review and eliminate all unnecessary BiDi control characters from source files.\n(3) Report any identified malicious Unicode BiDi control character usage to your cyber security team.\n(4) Review compilers, interpreters, and source code/viewers editors for vulnerabilities related to either interpreting or viewing Unicode BiDi control characters.\n(5) Apply any necessary patches for compilers, interpreters, and source code editors/viewers.\n\n\n## Tips\n\nNot available\n\n## References\n\n1. Trojan Source: Invisible Vulnerabilities, Nicholas Boucher, and R. Anderson, https://www.trojansource.codes/trojan-source.pdf\n2. CWE ID 451, Standards Mapping - Common Weakness Enumeration\n3. A1 Injection, Standards Mapping - OWASP Top 10 2017\n4. A03 Injection, Standards Mapping - OWASP Top 10 2021\n5. SWC-130, Standards Mapping - Smart Contract Weakness Classification\n\n\nCopyright (c) 2025 Open Text\n"
            }
        },
        {
            "id": "A8DBA2E8-A162-4A52-B854-046A8EE5ECB9",
            "shortDescription": {
            "text": "Insecure Randomness"
            },
            "fullDescription": {
            "text": "## Insecure Randomness\n\nStandard pseudorandom number generators cannot withstand cryptographic attacks.\n"
            },
            "help": {
            "text": "Insecure randomness errors occur when a function that can produce predictable values is used as a source of randomness in a security-sensitive context.\n\nComputers are deterministic machines, and as such are unable to produce true randomness. Pseudorandom Number Generators (PRNGs) approximate randomness algorithmically, starting with a seed from which subsequent values are calculated.\n\nThere are two types of PRNGs: statistical and cryptographic. Statistical PRNGs provide useful statistical properties, but their output is highly predictable and form an easy to reproduce numeric stream that is unsuitable for use in cases where security depends on generated values being unpredictable. Cryptographic PRNGs address this problem by generating output that is more difficult to predict. For a value to be cryptographically secure, it must be impossible or highly improbable for an attacker to distinguish between the generated random value and a truly random value. In general, if a PRNG algorithm is not advertised as being cryptographically secure, then it is probably a statistical PRNG and should not be used in security-sensitive contexts, where its use can lead to serious vulnerabilities such as easy-to-guess temporary passwords, predictable cryptographic keys, session hijacking, and DNS spoofing.\n\nExample: The following code uses a statistical PRNG to create a URL for a receipt that remains active for some period of time after a purchase.\n\n\n\n    def genReceiptURL(self,baseURL):\n    randNum = random.random()\n    receiptURL = baseURL + randNum + \".html\"\n    return receiptURL\n\n\nThis code uses the `rand()` function to generate \"unique\" identifiers for the receipt pages it generates. Since `rand()` is a statistical PRNG, it is easy for an attacker to guess the strings it generates. Although the underlying design of the receipt system is also faulty, it would be more secure if it used a random number generator that did not produce predictable receipt identifiers, such as a cryptographic PRNG.\n\n## Recommendations\n\nWhen unpredictability is critical, as is the case with most security-sensitive uses of randomness, use a cryptographic PRNG. Regardless of the PRNG you choose, always use a value with sufficient entropy to seed the algorithm. (Do not use values such as the current time because it offers only negligible entropy.)\n\n## Tips\n\nNot available\n\n## References\n\n1. Building Secure Software, J. Viega, G. McGraw\n2. CWE ID 338, Standards Mapping - Common Weakness Enumeration\n3. CCI-002450, Standards Mapping - DISA Control Correlation Identifier Version 2\n4. MP, Standards Mapping - FIPS200\n5. Insufficient Data Protection, Standards Mapping - General Data Protection Regulation\n6. SC-13 Cryptographic Protection (P1), Standards Mapping - NIST Special Publication 800-53 Revision 4\n7. SC-13 Cryptographic Protection, Standards Mapping - NIST Special Publication 800-53 Revision 5\n8. 2.3.1 Authenticator Lifecycle Requirements (L1 L2 L3), 2.6.2 Look-up Secret Verifier Requirements (L2 L3), 3.2.2 Session Binding Requirements (L1 L2 L3), 3.2.4 Session Binding Requirements (L2 L3), 6.3.1 Random Values (L2 L3), 6.3.2 Random Values (L2 L3), 6.3.3 Random Values (L3), Standards Mapping - OWASP Application Security Verification Standard 4.0\n9. MASVS-CRYPTO-1, Standards Mapping - OWASP Mobile Application Security Verification Standard 2.0\n10. M6 Broken Cryptography, Standards Mapping - OWASP Mobile Top 10 Risks 2014\n11. M10 Insufficient Cryptography, Standards Mapping - OWASP Mobile Top 10 Risks 2023\n12. M10 Insufficient Cryptography, Standards Mapping - OWASP Mobile Top 10 Risks 2024\n13. A8 Insecure Storage, Standards Mapping - OWASP Top 10 2004\n14. A8 Insecure Cryptographic Storage, Standards Mapping - OWASP Top 10 2007\n15. A7 Insecure Cryptographic Storage, Standards Mapping - OWASP Top 10 2010\n16. A02 Cryptographic Failures, Standards Mapping - OWASP Top 10 2021\n17. Requirement 6.5.8, Standards Mapping - Payment Card Industry Data Security Standard Version 1.1\n18. Requirement 6.3.1.3, Requirement 6.5.8, Standards Mapping - Payment Card Industry Data Security Standard Version 1.2\n19. Requirement 6.5.3, Standards Mapping - Payment Card Industry Data Security Standard Version 2.0\n20. Requirement 6.5.3, Standards Mapping - Payment Card Industry Data Security Standard Version 3.0\n21. Requirement 6.5.3, Standards Mapping - Payment Card Industry Data Security Standard Version 3.1\n22. Requirement 6.5.3, Standards Mapping - Payment Card Industry Data Security Standard Version 3.2\n23. Requirement 6.5.3, Standards Mapping - Payment Card Industry Data Security Standard Version 3.2.1\n24. Requirement 6.2.4, Standards Mapping - Payment Card Industry Data Security Standard Version 4.0\n25. Control Objective 7.3 - Use of Cryptography, Standards Mapping - Payment Card Industry Software Security Framework 1.0\n26. Control Objective 7.3 - Use of Cryptography, Control Objective B.2.4 - Terminal Software Design, Standards Mapping - Payment Card Industry Software Security Framework 1.1\n27. Control Objective 7.3 - Use of Cryptography, Control Objective B.2.4 - Terminal Software Design, Standards Mapping - Payment Card Industry Software Security Framework 1.2\n28. Porous Defenses - CWE ID 330, Standards Mapping - SANS Top 25 2009\n29. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.1\n30. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.10\n31. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.4\n32. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.5\n33. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.6\n34. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.7\n35. APP3150.2 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.9\n36. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.1\n37. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.10\n38. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.11\n39. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.2\n40. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.3\n41. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.4\n42. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.5\n43. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.6\n44. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.7\n45. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.8\n46. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.9\n47. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.1\n48. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.2\n49. APSC-DV-002010 CAT II, APSC-DV-002050 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.3\n\n\nCopyright (c) 2025 Open Text\n"
            }
        },
        {
            "id": "E8308B29-498A-4DDC-9661-AFD14E98A230",
            "shortDescription": {
            "text": "Insecure SSL: Server Identity Verification Disabled"
            },
            "fullDescription": {
            "text": "## Insecure SSL: Server Identity Verification Disabled\n\nServer identity verification is disabled when making SSL connections.\n"
            },
            "help": {
            "text": "In some libraries that use SSL connections, it is possible to disable server certificate verification. This is equivalent to trusting all certificates.\n\nExample 1: This application does not verify server certificate by default:\n\n\n\n    ...\n    import ssl\n    ssl_sock = ssl.wrap_socket(s)\n    ...\n\n\nWhen trying to connect to a valid host, this application would readily accept a certificate issued to \"hackedserver.com\". The application would now potentially leak sensitive user information on a broken SSL connection to the hacked server.\n\n## Recommendations\n\nDo not forget server verification checks when making SSL connections. Depending on the library used, make sure to verify server identity and establish a secure SSL connection.\n\nExample 2: This application does explicitly verify the server certificate.\n\n\n\n    ...\n    ssl_sock = ssl.wrap_socket(s, ca_certs=\"/etc/ca_certs_file\", cert_reqs=ssl.CERT_REQUIRED)\n    ...\n\n\n\n## Tips\n\nNot available\n\n## References\n\n1. RFC 6125: Representation and Verification of Domain-Based Application Service Identity within Internet Public Key Infrastructure Using X.509 (PKIX) Certificates in the Context of Transport Layer Security (TLS), P. Saint-Andre and J. Hodges, https://tools.ietf.org/html/rfc6125\n2. PEP 476 - Enabling certificate verification by default for stdlib http clients., Python Software Foundation, https://www.python.org/dev/peps/pep-0476/\n3. CWE ID 297, Standards Mapping - Common Weakness Enumeration\n4. [13] CWE ID 287, [25] CWE ID 295, Standards Mapping - Common Weakness Enumeration Top 25 2019\n5. [14] CWE ID 287, Standards Mapping - Common Weakness Enumeration Top 25 2020\n6. [14] CWE ID 287, Standards Mapping - Common Weakness Enumeration Top 25 2021\n7. [14] CWE ID 287, Standards Mapping - Common Weakness Enumeration Top 25 2022\n8. [13] CWE ID 287, Standards Mapping - Common Weakness Enumeration Top 25 2023\n9. CCI-000185, CCI-001941, CCI-001942, CCI-002418, CCI-002420, CCI-002421, CCI-002422, Standards Mapping - DISA Control Correlation Identifier Version 2\n10. CM, SC, Standards Mapping - FIPS200\n11. Insufficient Data Protection, Standards Mapping - General Data Protection Regulation\n12. SC-8 Transmission Confidentiality and Integrity (P1), Standards Mapping - NIST Special Publication 800-53 Revision 4\n13. SC-8 Transmission Confidentiality and Integrity, Standards Mapping - NIST Special Publication 800-53 Revision 5\n14. API8 Security Misconfiguration, Standards Mapping - OWASP API Top 10 2023\n15. 2.6.3 Look-up Secret Verifier Requirements (L2 L3), 2.7.1 Out of Band Verifier Requirements (L1 L2 L3), 2.7.2 Out of Band Verifier Requirements (L1 L2 L3), 2.7.3 Out of Band Verifier Requirements (L1 L2 L3), 2.8.4 Single or Multi Factor One Time Verifier Requirements (L2 L3), 2.8.5 Single or Multi Factor One Time Verifier Requirements (L2 L3), 3.7.1 Defenses Against Session Management Exploits (L1 L2 L3), 6.2.1 Algorithms (L1 L2 L3), 9.2.1 Server Communications Security Requirements (L2 L3), 9.2.3 Server Communications Security Requirements (L2 L3), Standards Mapping - OWASP Application Security Verification Standard 4.0\n16. MASVS-NETWORK-1, MASVS-PLATFORM-2, Standards Mapping - OWASP Mobile Application Security Verification Standard 2.0\n17. M3 Insufficient Transport Layer Protection, Standards Mapping - OWASP Mobile Top 10 Risks 2014\n18. M5 Insecure Communication, Standards Mapping - OWASP Mobile Top 10 Risks 2023\n19. M5 Insecure Communication, Standards Mapping - OWASP Mobile Top 10 Risks 2024\n20. A3 Broken Authentication and Session Management, Standards Mapping - OWASP Top 10 2004\n21. A9 Insecure Communications, Standards Mapping - OWASP Top 10 2007\n22. A9 Insufficient Transport Layer Protection, Standards Mapping - OWASP Top 10 2010\n23. A6 Sensitive Data Exposure, Standards Mapping - OWASP Top 10 2013\n24. A3 Sensitive Data Exposure, Standards Mapping - OWASP Top 10 2017\n25. A07 Identification and Authentication Failures, Standards Mapping - OWASP Top 10 2021\n26. Requirement 4.1, Requirement 6.5.10, Standards Mapping - Payment Card Industry Data Security Standard Version 1.1\n27. Requirement 4.1, Requirement 6.3.1.4, Requirement 6.5.9, Standards Mapping - Payment Card Industry Data Security Standard Version 1.2\n28. Requirement 4.1, Requirement 6.5.4, Standards Mapping - Payment Card Industry Data Security Standard Version 2.0\n29. Requirement 4.1, Requirement 6.5.4, Standards Mapping - Payment Card Industry Data Security Standard Version 3.0\n30. Requirement 4.1, Requirement 6.5.4, Standards Mapping - Payment Card Industry Data Security Standard Version 3.1\n31. Requirement 4.1, Requirement 6.5.4, Standards Mapping - Payment Card Industry Data Security Standard Version 3.2\n32. Requirement 4.1, Requirement 6.5.4, Standards Mapping - Payment Card Industry Data Security Standard Version 3.2.1\n33. Requirement 4.2.1, Requirement 6.2.4, Standards Mapping - Payment Card Industry Data Security Standard Version 4.0\n34. Control Objective 3.3 - Sensitive Data Retention, Control Objective 6.2 - Sensitive Data Protection, Control Objective 7.1 - Use of Cryptography, Standards Mapping - Payment Card Industry Software Security Framework 1.0\n35. Control Objective 3.3 - Sensitive Data Retention, Control Objective 6.2 - Sensitive Data Protection, Control Objective 7.1 - Use of Cryptography, Control Objective B.2.3 - Terminal Software Design, Standards Mapping - Payment Card Industry Software Security Framework 1.1\n36. Control Objective 3.3 - Sensitive Data Retention, Control Objective 6.2 - Sensitive Data Protection, Control Objective 7.1 - Use of Cryptography, Control Objective B.2.3 - Terminal Software Design, Control Objective C.4.1 - Web Software Communications, Standards Mapping - Payment Card Industry Software Security Framework 1.2\n37. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.1\n38. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.10\n39. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.4\n40. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.5\n41. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.6\n42. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.7\n43. APP3250.1 CAT I, APP3250.2 CAT I, APP3250.3 CAT II, APP3250.4 CAT II, Standards Mapping - Security Technical Implementation Guide Version 3.9\n44. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.1\n45. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.10\n46. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.11\n47. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.2\n48. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.3\n49. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.4\n50. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.5\n51. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.6\n52. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.7\n53. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.8\n54. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.9\n55. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.1\n56. APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.2\n57. APSC-DV-000590 CAT II, APSC-DV-001620 CAT II, APSC-DV-001630 CAT II, APSC-DV-001810 CAT I, APSC-DV-002440 CAT I, APSC-DV-002450 CAT II, APSC-DV-002460 CAT II, APSC-DV-002470 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.3\n58. Information Leakage, Standards Mapping - Web Application Security Consortium 24 + 2\n59. Insufficient Transport Layer Protection (WASC-04), Standards Mapping - Web Application Security Consortium Version 2.00\n\n\nCopyright (c) 2025 Open Text\n"
            }
        },
        {
            "id": "580AE6A3-5731-4F1E-B64D-2E29C029B3FE",
            "shortDescription": {
            "text": "Insecure Temporary File"
            },
            "fullDescription": {
            "text": "## Insecure Temporary File\n\nCreating and using insecure temporary files can leave application and system data vulnerable to attacks.\n"
            },
            "help": {
            "text": "Applications require temporary files so frequently that many different mechanisms exist for creating them. Most of these functions are vulnerable to various forms of attacks.\n\nExample: The following code uses a temporary file for storing intermediate data gathered from the network before it is processed.\n\n\n\n    ...\n    try:\n    tmp_filename = os.tempnam()\n    tmp_file = open(tmp_filename, 'w')\n    data = s.recv(4096)\n    while True:\n    more = s.recv(4096)\n    tmp_file.write(more)\n    if not more:\n    break\n    except socket.timeout:\n    errMsg = \"Connection timed-out while connecting\"\n    self.logger.exception(errMsg)\n    raise Exception\n    ...\n\n\nThis otherwise unremarkable code is vulnerable to a number of different attacks because it relies on an insecure method for creating temporary files. The vulnerabilities introduced by this function and others are described in the following sections. The most egregious security problems related to temporary file creation have occurred on Unix-based operating systems, but Windows applications have parallel risks.\n\nMethods and behaviors can vary between systems, but the fundamental risks introduced by each are reasonably constant. See the Recommendations section for information about safe core language functions and advice regarding a secure approach to creating temporary files.\n\nThe functions designed to aid in the creation of temporary files can be broken into two groups based on whether they simply provide a filename or actually open a new file.\n\nGroup 1 - \"Unique\" Filenames:\n\nThe first group of functions designed to help with the process of creating temporary files do so by generating a unique file name for a new temporary file, which the program is then supposed to open. This group of functions suffers from an underlying race condition on the filename chosen. Although the functions guarantee that the filename is unique at the time it is selected, there is no mechanism to prevent another process or an attacker from creating a file with the same name after it is selected but before the application attempts to open the file. Beyond the risk of a legitimate collision caused by another call to the same function, there is a high probability that an attacker will be able to create a malicious collision because the filenames generated by these functions are not sufficiently randomized to make them difficult to guess.\n\nIf a file with the selected name is created, then depending on how the file is opened the existing contents or access permissions of the file may remain intact. If the existing contents of the file are malicious in nature, an attacker may be able to inject dangerous data into the application when it reads data back from the temporary file. If an attacker pre-creates the file with relaxed access permissions, then data stored in the temporary file by the application may be accessed, modified or corrupted by an attacker. On Unix based systems an even more insidious attack is possible if the attacker pre-creates the file as a link to another important file. Then, if the application truncates or writes data to the file, it may unwittingly perform damaging operations for the attacker. This is an especially serious threat if the program operates with elevated permissions.\n\nFinally, in the best case the file will be opened with a call to `open()` using the `os.O_CREAT` and `os.O_EXCL` flags, which will fail if the file already exists and therefore prevent the types of attacks described previously. However, if an attacker is able to accurately predict a sequence of temporary file names, then the application may be prevented from opening necessary temporary storage causing a denial of service (DoS) attack. This type of attack would not be difficult to mount given the small amount of randomness used in the selection of the filenames generated by these functions.\n\nGroup 2 - \"Unique\" Files:\n\nThe second group of functions attempts to resolve some of the security problems related to temporary files by not only generating a unique file name, but also opening the file. This group includes functions like `tmpfile()`.\n\nThe `tmpfile()` style functions construct a unique filename and open it in the same way that `open()` would if passed the flags `\"wb+\"`, that is, as a binary file in read/write mode. If the file already exists, `tmpfile()` will truncate it to size zero, possibly in an attempt to assuage the security concerns mentioned earlier regarding the race condition that exists between the selection of a supposedly unique filename and the subsequent opening of the selected file. However, this behavior clearly does not solve the function's security problems. First, an attacker may pre-create the file with relaxed access-permissions that will likely be retained by the file opened by `tmpfile()`. Furthermore, on Unix based systems if the attacker pre-creates the file as a link to another important file, the application may use its possibly elevated permissions to truncate that file, thereby doing damage on behalf of the attacker. Finally, if `tmpfile()` does create a new file, the access permissions applied to that file will vary from one operating system to another, which can leave application data vulnerable even if an attacker is unable to predict the filename to be used in advance.\n\n## Recommendations\n\nUsage of `tempfile.mkstemp()` and `tempfile.mkdtemp()` are the best choices for temporary file creation among the functions offered out-of-the-box. Both functions create a temporary file in the most secure manner possible. There are no race conditions in the file's creation, assuming that the platform properly implements the `os.O_EXCL` flag for `os.open()`. The file is readable and writable only by the creating user ID. If the platform uses permission bits to indicate whether a file is executable, the file is executable by no one. The file descriptor is not inherited by child processes.\n\n## Tips\n\nNot available\n\n## References\n\n1. Yarrow: A secure pseudorandom number generator, B. Schneier, http://www.schneier.com/yarrow.html\n2. Python Library Reference: os, https://docs.python.org/2/library/os.html\n3. Python Library Reference: tempfile, https://docs.python.org/2/library/tempfile.html\n4. Symlink race, http://en.wikipedia.org/wiki/Symlink_race\n5. Time of check to time of use, http://en.wikipedia.org/wiki/Time_of_check_to_time_of_use\n6. CWE ID 377, Standards Mapping - Common Weakness Enumeration\n7. CCI-001090, Standards Mapping - DISA Control Correlation Identifier Version 2\n8. Indirect Access to Sensitive Data, Standards Mapping - General Data Protection Regulation\n9. SC-4 Information in Shared Resources (P1), Standards Mapping - NIST Special Publication 800-53 Revision 4\n10. SC-4 Information in Shared System Resources, Standards Mapping - NIST Special Publication 800-53 Revision 5\n11. Requirement 3.3.1, Requirement 3.5.1, Standards Mapping - Payment Card Industry Data Security Standard Version 4.0\n12. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.1\n13. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.10\n14. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.11\n15. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.2\n16. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.3\n17. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.4\n18. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.5\n19. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.6\n20. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.7\n21. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.8\n22. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 4.9\n23. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.1\n24. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.2\n25. APSC-DV-002380 CAT II, Standards Mapping - Security Technical Implementation Guide Version 5.3\n\n\nCopyright (c) 2025 Open Text\n"
            }
        }
    ]
    expected = {
        "11BF839E-A56A-4CA7-BFD2-9AC137C69F060": {"CWE-77", "CWE-78"},
        "28AC7755-F497-4170-A394-8404B81A92A9": {"CWE-451"},
        "A8DBA2E8-A162-4A52-B854-046A8EE5ECB9": {"CWE-338", "CWE-330"},
        "E8308B29-498A-4DDC-9661-AFD14E98A230" : {"CWE-297", "CWE-287", "CWE-295"},
        "580AE6A3-5731-4F1E-B64D-2E29C029B3FE" : {"CWE-377"}
    }
    actual = sarif_to_rule_map(fod_rules)
    # for k,v in actual.items():
    #     print(f"{k}: {v}")
    assert len(actual) == len(expected), f"Expected: {len(expected)}; Got: {len(actual)}"
    for k in actual.keys():
        assert expected[k] == actual[k], f"Expected: {expected[k]}; Got: {actual[k]}"
    

def test_sarif_to_df_bandit():
    bandit_sarif_path = Path("test_data\\bandit-results-jan27.sarif")
    
def test_sarif_to_df_fod_py():
    fod_py_sarif_path = Path("test_data\\py-gh-fortify-sast-jan27.sarif")
    
def test_sarif_to_df_fod_py():
    fod_java_sarif_path = Path("test_data\\java-gh-fortify-sast-jan27.sarif")
    
def test_sarif_to_df_spotbugs():
    spotbugs_sarif_path = Path("test_data\\spotbugsSarif-jan27.json")

def test_get_metrics_fod_py():
    fod_py_sarif_path = Path("test_data\\py-gh-fortify-sast-jan27.sarif")
    print(f"FOD Python - {str(fod_py_sarif_path)}")
    fod_py_df = sarif_to_df(Path("test_data\\py-gh-fortify-sast-jan27.sarif"))

    num_critical = len(fod_py_df[ fod_py_df['severity'] == "CRITICAL" ])
    num_critical = len(fod_py_df[ fod_py_df['severity'] == "CRITICAL" ])
    num_top_25 = len(fod_py_df[ fod_py_df['hasCWETop25'] == True ])


if __name__ == "__main__":
    test_sarif_to_rule_map_bandit()
    test_sarif_to_rule_map_spotbugs()
    test_sarif_to_rule_map_fortify()