# -*- coding: utf-8 -*-
"""
Created on Sat Feb  1 05:57:18 2020

@author: Jerry
"""

import pandas as pd
from generalFunctions import exportCSV,get_general_html
import os
import glob
import bs4
from collections import OrderedDict
    
domain = 'https://www.cvedetails.com'

path = 'cve_vulnerability'
os.chdir(path)
extension = 'csv'
all_filenames = [i for i in glob.glob('*.{}'.format(extension))]

for filename in all_filenames[10:]:
    '''Convert dataframe to list of dictionary'''
    lt_cve = pd.read_csv(filename).to_dict('records')
    gt_product = []
    for ls_cve in lt_cve:
        gs_product = OrderedDict({key:ls_cve[key] for key in ls_cve.keys() if key != 'CVE_Link'})
        next_url = domain + ls_cve['CVE_Link']   
        product_content = get_general_html(next_url)
        product_soup = bs4.BeautifulSoup(product_content, 'lxml')
        prod_table = product_soup.find('table', class_="listtable",id="vulnprodstable").find_all('tr')
        if len(prod_table) > 1:
            previous_product = OrderedDict()
            headers = [header.text for header in prod_table[0].find_all('th')]
            for row in prod_table[1:]:
                cols = [value.text.strip() for value in row.find_all('td')]
                cve_product = OrderedDict({key:value for key,value in zip(headers, cols) if key in ['Product Type','Vendor','Product']})
                if previous_product != cve_product:
                    gt_product.append(OrderedDict(**gs_product, **cve_product).copy())
                previous_product = cve_product
    if gt_product:
        path = 'cve_product'
        print(filename+' No of vulnerabilities:'+str(len(lt_cve))+' No of details:'+str(len(gt_product)))
        filename_prod = filename.split('.',1)[0] + '_details.' + filename.split('.',1)[1]
        exportCSV(gt_product,filename_prod,path)
        