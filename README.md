# Shodan.io Port Scanning

A simple python script to scan multiple IPs through Shodan using the search API.

## Usage

- Open shoscan.py and update your `SHODAN_API_KEY` value.
- pip install -r requirements.txt
- python shoscan.py -f inputIpListFile.txt
- Enjoy your results in csv files and in your console

## Todos

- Remove duplicates from the full results.csv
- Support other search function from Shodan API?

## Help making this little tool better?

Please submit issues with your Pull Requests

### Full results: SHODAN Search Response - Data Returned
- city
- region_code
- os
- tags
- ip
- isp
- area_code
- dma_code
- last_update
- country_code3
- country_name
- hostnames
- postal_code
- longitude
- country_code
- ip_str
- latitude
- org
- data
  - asn
  - hash
  - tags
  - ip
  - isp
  - transport
  - data
  - port
  - ssl
  - hostnames
  - location
  - timestamp
  - domains
  - org
  - os
  - _shodan
  - opts
  - ip_str
- asn
- ports

