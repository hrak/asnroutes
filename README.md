## asnroutes
`asnroutes` fetches all routing prefixes announced by an ASN from RADB. The routes are then aggregated by eliminating overlapping subnets.

The main goal for this tool is to create ACLs or firewall rules

## Usage
Usage of `asnroutes`

```
  asnroutes -as 1234[,5678,...]
  -as value
    	List of AS numbers (comma seperated)
```

## Example
To get a list of prefixes announced by AS59253:

```
./asnroutes -as 59253
209.58.176.0/21
43.249.38.0/23
103.35.182.0/23
103.254.153.0/24
155.254.221.0/24
192.253.255.0/24
103.254.153.0/24
103.47.145.0/24
103.55.8.0/24
43.246.113.0/24
2001:df1:800::/48
```

## Contribution Guidelines
Feel free to open an issue or a pull request if you have something to contribute or comment on. Since this is one of my first Go projects, I'm open to suggestions and comments.

## Author
Hans Rakers (@hrak) 2015