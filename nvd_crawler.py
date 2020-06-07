from bs4 import BeautifulSoup
import requests
import sys

if (len(sys.argv) <= 1):
    print('Usage: {} query'.format(sys.argv[0]))
    sys.exit(0)

result_num = 1
page_through = 0
nvd_params = {'form_type': 'Basic', 'results_type': 'overview', 'query': '', 'search_type': 'all', 'startIndex': 0}
nvd_params['query'] = sys.argv[1]
while (page_through < result_num):
    nvd_params['startIndex'] = page_through
    nvd_url = 'https://nvd.nist.gov/vuln/search/results'
    html_doc = requests.get(nvd_url, params=nvd_params).text
    soup = BeautifulSoup(html_doc, 'html.parser')
    result_num = soup.select("#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilitySearchResults_VulnResultsPanel")[0].select("strong[data-testid=vuln-matching-records-count]")[0].text
    result_num = int(result_num)
    print('result num:', result_num)
    page_from = soup.select("#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilitySearchResults_ResultsNumbersPanel")[0].select("strong[data-testid=vuln-displaying-count-from]")[0].text
    page_through = soup.select("#p_lt_WebPartZone1_zoneCenter_pageplaceholder_p_lt_WebPartZone1_zoneCenter_VulnerabilitySearchResults_ResultsNumbersPanel")[0].select("strong[data-testid=vuln-displaying-count-through]")[0].text
    page_from = int(page_from)
    page_through = int(page_through)
    print('from', page_from, 'through', page_through)
    soup_cve_list = soup.select("#row")[0]
    cve_list = []
    for i in range(page_from - page_from, page_through - page_from):
        soup_cve_list_row = soup_cve_list.select("tr[data-testid=vuln-row-{}]".format(i))[0]
        cve = {}
        cve['link'] = soup_cve_list_row.select("th a")[0]['href']
        cve['CVE-ID'] = soup_cve_list_row.select("th a")[0].text
        cve['summary'] = soup_cve_list_row.select("p[data-testid=vuln-summary-{}]".format(i))[0].text
        cve['CVSS'] = soup_cve_list_row.select("td[nowrap=nowrap]")[0].text
        cve['CVSS'] = cve['CVSS'].replace('\n', ' ')
        print('{}\t{}\t{}'.format(cve['CVE-ID'], cve['summary'][:50], cve['CVSS']))
        cve_list.append(cve)
