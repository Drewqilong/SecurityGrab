# -*- coding: utf-8 -*-
"""
Created on Fri Jan 31 11:49:55 2020

@author: Jerry
"""

import bs4
import re
from collections import OrderedDict
from generalFunctions import exportCSV

domain = 'https://www.cvedetails.com'

'''Request url'''    
def get_html(url):
    import requests
    '''
    封装请求
    '''
    headers = {
        'User-Agent':
        'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.79 Safari/537.36',
#        'cookie':
#        '__cfduid=d95896e149fb4dc7048bb7dc3fc30f9861576607394; xf_user=1284121%2C96e54c148af23da29089bba8910561a8c89b6a90; xf_session=511de6204544d8a81648fcd3e16460cd',
#        'authority': 
#        'www.beeradvocate.com'
#        'ContentType':
#        'text/html; charset=utf-8',
#        'Accept-Encoding':
#        'gzip, deflate, br',
#        'Accept-Language':
#        'zh-CN,zh;q=0.9,en;q=0.8',
#        'Connection':
#        'keep-alive',
    }
    try:
        session_requests = requests.session()
        htmlcontet = session_requests.get(url, headers=headers, timeout=30)
        htmlcontet.raise_for_status()
        htmlcontet.encoding = 'utf-8'
        return htmlcontet.text
    except:
        return " Request Failure "
    
gt_vul_year = []
''' Get All Vulnerabilitie link'''
next_url = domain+'/browse-by-date.php'
cve_content = get_html(next_url)
cve_soup = bs4.BeautifulSoup(cve_content, 'lxml')
cve_table = cve_soup.find('table', class_='stats').find_all('tr', {"onmouseover" : re.compile(r".*")})
gs_vul_year = OrderedDict()
for singleyear in cve_table:
    gs_vul_year['YearLink'] = singleyear.find('th').find('a').attrs['href']
    gs_vul_year['TotalNO'] = singleyear.find('td', class_='num').text.replace('\n','').strip()
    gt_vul_year.append(gs_vul_year.copy())

gt_cve = []
'''Get Vulnerabilities by year'''
for vul_year in gt_vul_year[:1]:
    next_url = domain+vul_year['YearLink']
    vuls_content = get_html(next_url)
    vuls_soup = bs4.BeautifulSoup(vuls_content, 'lxml')
    gt_pages = [[element.attrs['href'], element.text] for element in vuls_soup.find('div', class_='paging', id = 'pagingb' ).find_all('a')]
    pages = len(gt_pages)
    indx = 0
    while indx < pages:
        '''Header'''
        headers = [element.text.strip() for element in vuls_soup.find('table', class_='searchresults sortable', id='vulnslisttable').find('tr').find_all('th')]
        cve_rows = vuls_soup.find('table', class_='searchresults sortable', id='vulnslisttable').find_all('tr', class_='srrowns')
        for row in cve_rows:
            cols = [element.text.strip() for element in row.find_all('td')]
            if cols[4] and cols[4][0] in ['-','+']:cols[4] = '\'' + cols[4]
            cve_record = OrderedDict(zip(headers, cols))
            gt_cve.append(cve_record.copy())
        indx+=1
        if gt_pages[indx:indx+1]:
            page = gt_pages[indx]
            next_url = domain+page[0]
            vuls_content = get_html(next_url)
            vuls_soup = bs4.BeautifulSoup(vuls_content, 'lxml')

if gt_cve:
    path = 'cve_vulnerability'
    filename_review = 'cve_list.csv'
    exportCSV(gt_cve,filename_review,path)
        
    
    
