autorecon_wrapper:
  description: 'Processes AutoRecon results with custom SecurityScanner checks'
  usage: 'python autorecon_processor.py'

setup:
  - Install AutoRecon: pipx install autorecon
  - Run: autorecon platacard.mx
  - Process: python autorecon_processor.py

features:
  - Parses Nmap XML for HTTP services
  - Runs your hardcoded_secrets + sql_injection checks
  - Generates prioritized report

next:
  - Add GraphQL introspection
  - JWT secret validation
  - Cloud metadata endpoint checks