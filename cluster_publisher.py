import csv
import sys
import nltk
import re
# import distance
# import Levenshtein
import editdistance
import tldextract

THRESHOLD_FLAGGED_VT = 4
THRESHOLD_TOKEN_SIZE = 3
THRESHOLD_JACCARD_INDEX = 0.5
THRESHOLD_EDIT_DIS = 0.1

def calc_jaccard_index(list1, list2):
    '''
    Calculate the jaccard index
    '''
    set1 = set(list1)
    set2 = set(list2)
    return len(set1.intersection(set2)) / float(len(set1.union(set2)))

def get_list_signed(wine_file):
    '''
    Get a dictionary (key: id, value: publisher) of signed and PUP file
    and flagged by at least 4 AVs.

    Args:
        wine_file   -- the wine file name

    Returns:
        A dict      -- key: id, value: publihser name
    '''
    list_signed = {}
    with open(wine_file) as wine_f:
        reader = csv.reader(wine_f)
        next(reader, None)
        for row in reader:
            id = row[0]
            verified = row[2]
            positive = row[4]
            publisher = row[3]
            if verified == 'Signed' and int(positive) >= THRESHOLD_FLAGGED_VT:
                list_signed[id] = publisher
    return list_signed

def calc_edit_dis(cluster, tokens, id):
    '''
    Calculate edit distance and if the normalized_edit_distance is less than 0.1
    the id is appended to the cluster.

    Args:
        cluster     -- key: publihser, value: ids
        tokens      -- tokens of publisher
        id          -- id

    Returns:
        True if found a pair of two token's normalized_edit_distance < 0.1

    '''
    for key, value in cluster.iteritems():
        key_token = nltk.word_tokenize(key)
        for i in xrange(0, len(key_token)):
            for j in xrange(0, len(tokens)):
                ed = editdistance.eval(tokens[j], key_token[i])
                normalized_ed = float(ed)/float(max(len(tokens[j]), len(key_token[i])))
                if normalized_ed < THRESHOLD_EDIT_DIS:
                    cluster[key].append(id)
                    return True
    return False

def cluster_pub_similarity(wine_file):
    """
    Figure out the similarity between two publishers and cluster them
    """
    com_ext = ['ltd', 'limited', 'inc', 'corp', 'co', 'company', 'network', 'technology', 'corporation']
    article = ['the']
    geo_loc = []
    open_source = 'Open Source Developer'

    cluster = {} # key: token, value: array of IDs
    num_row = 0
    with open(wine_file) as wine_f:
        reader = csv.reader(wine_f)
        next(reader, None) # skip the header
        for row in reader:
            # row[3]: the name of the publisher
            # row[4](positive): how many were detected in VT
            # According to the paper (Usenix 16), they consider PUP any signed
            # file flagged by at least 4 AV engines.
            id = row[0]
            verified = row[2]
            publisher = row[3]
            positive = row[4]
            if (len(publisher) > 0 and publisher != open_source
                and int(positive) >= THRESHOLD_FLAGGED_VT
                and verified == 'Signed'):
                # print len(row[3]), row[3], row[4]
                publisher_tokens = nltk.word_tokenize(publisher.lower())
                tokens = []
                for tok in publisher_tokens:
                    t = re.sub('[^0-9a-zA-Z]+', '', tok)
                    if (len(t) >= THRESHOLD_TOKEN_SIZE
                        and (t not in com_ext) and (t not in geo_loc)
                        and (t not in tokens)) and (t not in article):
                        tokens.append(t)
                # print tokens
                num_row += 1

                if calc_edit_dis(cluster, tokens, id) is False:
                    key = ''
                    for t in tokens:
                        key += t + ' '
                    key = key[:len(key)-1]
                    cluster[key] = []
                    cluster[key].append(id)
    # num_cluster = 0
    # for key, values in cluster.iteritems():
    #     num_cluster += len(values)
    #     print key, values

    return cluster

def populate_cluster_dwn_domain(cluster, pub_dict):
    """
    Populate the cluster of child down domain

    Args:
        cluster     -- to be populated
        pub_dict    -- key: id, value: domain

    Returns:
        None
    """
    # print 'cluster: ', cluster
    # print 'pub_dict: ', pub_dict

    for i in xrange(0, len(cluster)):
        # cluster[i]: e.g. [{'Google': [{'2': 'symantec'}, {'6': 'google'}]}]
        for j in xrange(0, len(cluster[i])):
            cluster_domains = []
            pub_domains = []
            # cluster[i][j]:
            for domain_array in cluster[i][j].values(): #e.g. [{'2': 'symantec'}, {'6': 'google'}]
                for domain_dict in domain_array:
                    cluster_domains.append(domain_dict.values()[0])  # e.g. ['google'], ['symantec']
            for pub_domain_array in pub_dict.values():
                for pub_domain_dict in pub_domain_array:
                    pub_domains.append(pub_domain_dict.values()[0])
            jaccard_index = calc_jaccard_index(cluster_domains, pub_domains)
            if jaccard_index >= THRESHOLD_JACCARD_INDEX:
                cluster[i].append(pub_dict)
                return
    cluster.append([pub_dict])
    return

def cluster_dwn_domain(url_file, list_signed):
    """
    Cluster publishers using child or parent download domain

    Args:
        url_file    -- file name
        list_signed -- a list of executables signed and flagged by >= 4 AVs.

    Returns:
        A list      --
    """

    pubs_dict = {} # key: publisher, value: dict(key: id, value: domain)
    cluster = []
    with open(url_file) as u_f:
        reader = csv.reader(u_f)
        next(u_f, None)
        for row in reader:
            id = row[0]
            try:
                publisher = list_signed[id]
            except KeyError:
                continue
            url = row[1]
            tld = tldextract.extract(url)
            domain = tld[1]
            if publisher not in pubs_dict:
                pubs_dict[publisher] = []
            pubs_dict[publisher].append({id: domain})

    # calc Jaccard index
    for pub, domain_dict in pubs_dict.iteritems():
        pub_dict = {}
        pub_dict[pub] = domain_dict
        populate_cluster_dwn_domain(cluster, pub_dict)

    return cluster

    # sorted_cluster = sorted(cluster, key=len)
    # for c in sorted_cluster:
    #     print c


def get_common_names(path):
    """
    Get common names from X509

    Returns:
        A list -- common names
    """

    import cryptography
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    import os

    for file in os.listdir(path):
        if file.endswith('.der'):
            with open(path+'/'+file) as f:
                cert = cryptography.x509.load_der_x509_certificate(f.read(), default_backend())
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if len(cn) > 0:
                    cn_array.append(cn[0].value)
    return cn_array


def cluster_malsign(path):
    cn_array = get_common_names(path)

def extract_ids(pub_array):
    ids = []
    for pub_dict in pub_array:
        for p, d_dict in pub_dict.iteritems():
            for key in d_dict.keys():
                ids.append(ids)
    return ids

def find_id_from_dwn_domain(id, dwn_domain):
    """
    Find id in the list
    Returns
        list    -- if id is found in download domain, else None.
    """
    for pub_array in dwn_domain:    #pub_array: [{k: v}, {k: v}, ...]
        for pub_dict in pub_array:  #pub_dict: {p: [{id,domain},{id,domain}, ...]}
            for p, d_dict in pub_dict.iteritems():
                for d in d_dict:
                    key = d.keys()
                    if key == id: # ID is found in the list
                        return extract_ids(pub_array)
    return None

def find_id_from_pub_sim(id, pub_sim):
    for publisher, ids in pub_sim:
        if id in ids:
            return publisher
    return None

def final_cluster(pub_sim, child_dwn, parent_dwn, malsign_cn):
    """
    Final clustering
    Args:
        pub_sim     -- a dict of cluster (from publisher simiarity)
        child_dwn   -- a dict of cluster (from child download domain)
        parent_dwn  -- a dict of cluster (from parent download domain)

    Returns:
        A dict      -- key: publihser, value: ids
    """
    final_cluster = {} # key: publisher, value: array of ids

    for publisher, ids in pub_sim.iteritems():
        if len(ids) == 1:
            id_array = find_id_from_dwn_domain(ids[0], child_dwn)
            if id_array == None:
                id_array = find_id_from_dwn_domain(ids[0], parent_dwn)
            if id_array != None:
                for tmp_id in id_array:
                    publisher = find_id_from_pub_sim(tmp_id, pub_sim)
                    if publisher not in final_cluster.keys():
                        final_cluster[publisher] = []
                    final_cluster[publisher].append(ids[0])
                    break
        final_cluster[publisher] = ids

    return final_cluster

def dict_to_json(dict, file_name):
    import json
    with open(file_name, 'w') as out_f:
        json.dump(dict, out_f)

def json_to_dict(file_name):
    import json
    with open(file_name, 'r') as in_f:
        json_str = in_f.read()
        return json.loads(json_str)

if __name__ == '__main__':
    wine_file = '/scratch0/pup/data/filesha2.csv'
    child_url_file = '/scratch0/pup/data/child_url.csv'
    parent_url_file = '/scratch0/pup/data/parent_url.csv'
    # wine_file = './test_filesha2.csv'
    # child_url_file = './test_child_url.csv'

    # list_signed = get_list_signed(wine_file)
    # dict_to_json(list_signed, 'list_signed.json')
    list_signed = json_to_dict('list_signed.json')
    # keys = list_signed.keys()

    # child_dwn_dict = cluster_dwn_domain(child_url_file, list_signed)
    # dict_to_json(child_dwn_dict, 'child_dwn.json')
    child_dwn = json_to_dict('child_dwn.json')

    # parent_dwn_dict = cluster_dwn_domain(parent_url_file, list_signed)
    # dict_to_json(parent_dwn_dict, 'parent_dwn.json')
    parent_dwn = json_to_dict('child_dwn.json')

    # pub_sim = cluster_pub_similarity(wine_file)
    # dict_to_json(pub_sim, 'pub_sim.json')
    pub_sim = json_to_dict('pub_sim.json')

    total_num = 0
    single_num = 0
    # for k in keys:
    #     found = False
    #     for key, value in pub_sim.iteritems():
    #         if k in value:
    #             found = True
    #             break;
    #     if not found:
    #         print k

    # print total_num
    #
    f_c = final_cluster(pub_sim, child_dwn, parent_dwn, None)
    for k in sorted(f_c, key=lambda k: len(f_c[k]), reverse=True):
        print k, len(f_c[k]), f_c[k]
        if len(f_c[k]) == 1:
            single_num += 1
        total_num += len(f_c[k])

    print total_num, single_num

    # for key, value in f_c.iteritems():
    #     print key, value
