from nornir import InitNornir
import os.path
from nornir_utils.plugins.functions import print_result
from nornir_netmiko import netmiko_send_command,netmiko_send_config
from nornir.core.filter import F
import yaml,json,glob,ipaddress,re,pprint
from nornir.core.plugins.inventory import InventoryPluginRegister
#from nornir.plugins.inventory import InventoryPlugin

import logging
logger = logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()


#pp = pprint.PrettyPrinter(indent=4)

#InventoryPluginRegister.register("DictInventory", InventoryPlugin)

ASN = '100'
pool = '10.10.10.0/24'
prefix_len = 32
pool6 = '2001:db8::/122'
prefix_len6 = 128
loopback_pool = list(ipaddress.ip_network(pool).subnets(new_prefix=prefix_len))
loopback_pool6 = list(ipaddress.ip_network(pool6).subnets(new_prefix=prefix_len6))[1:]
# Remove the first zero address to avoid confusion
loopback_pool.pop(0)
pool = '192.168.0.0/23'
prefix_len = 31
pool6 = '2001:ffff::/120'
prefix_len6 = 127 
p2p_pool = list(ipaddress.ip_network(pool).subnets(new_prefix=prefix_len))
p2p_pool6 = list(ipaddress.ip_network(pool6).subnets(new_prefix=prefix_len6))

ipadd_regex =re.compile('''((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)''') 

clab_file = "*clab.yaml"
ansible_file = "clab*/*.yml"
inventory_data = '''
groups:
  ios:
      platform: 'ios'
      username: admin
      password: ""
      connection_options:
        netmiko:
           extras:
             ssh_config_file: /home/sbng/.ssh/config
'''

def check_files():
    try:
        files = glob.glob(ansible_file)
        assert len(files) > 0
        logger.info ("[INFO]: found " + files[0])
        files = glob.glob(clab_file) 
        assert len(files) > 0
        logger.info ("[INFO]: found " + files[0])
    except Exception as e: 
        logger.error ("[ERROR]: YAML files not found, please deploy containerlab")
    return

def get_inventory (inventory_data = inventory_data):
    inventory_dict = yaml.safe_load(inventory_data)
    yaml_inventory = open(glob.glob(ansible_file)[0])
    parse_yaml = yaml.load(yaml_inventory, Loader=yaml.FullLoader)
    routers = list(parse_yaml['all']['children']['linux']['hosts'].keys())
    for i in routers:
        parse_yaml['all']['children']['linux']['hosts'][i]["hostname"] = \
        parse_yaml['all']['children']['linux']['hosts'][i]["ansible_host"]
        parse_yaml['all']['children']['linux']['hosts'][i]["groups"] = ['ios']
        parse_yaml['all']['children']['linux']['hosts'][i]["name"] = [i]
    host_dict = parse_yaml['all']['children']['linux']
    return (inventory_dict, host_dict)

def get_nodes_by_role(role):
    '''
    get the label to discover the role of device
    '''
    yaml_file = open(glob.glob(clab_file)[0])
    parsed_yaml = yaml.load(yaml_file, Loader=yaml.FullLoader)
    routers = [router for router in parsed_yaml['topology']['nodes'] \
               if parsed_yaml['topology']['nodes'][router]['labels']['role'] == role]
    return routers

def get_endpoints (link_net):
    '''
    return all the endpoints from the clab config files. Total number of routers are
    also returned for reference
    '''
    yaml_file = open(glob.glob(clab_file)[0])
    parsed_yaml = yaml.load(yaml_file, Loader=yaml.FullLoader)
    links = list(parsed_yaml['topology']['links'])
    routers = list(parsed_yaml['topology']['nodes'])
    routers_name = ["clab-"+parsed_yaml['name']+"-"+x for x in routers]
    return (routers_name, links)

def config_p2p (routers, links, link_net, link_net6):
    def make_dict (ep_list, routers):
        host1 = ep_list[0].split(":")[0]
        host2 = ep_list[1].split(":")[0]
        host1_int = ep_list[0].split(":")[1]
        host2_int = ep_list[1].split(":")[1]
        rt1 = [ i for i in routers if host1 in i].pop(0)
        rt2 = [ i for i in routers if host2 in i].pop(0)
        return (rt1, rt2, host1_int, host2_int) 
    
    def create_dict (rt, conf):
        if rt not in conf.keys():
            conf[rt] = {}
            conf[rt]['interfaces'] = {}
        return conf
    
    def gen_config (rt, rt_int, host_address, host_address6, config):
        config[rt]['interfaces'][rt_int] = ["interface "+ str(rt_int)]
        config[rt]['interfaces'][rt_int].append("description connect to "+ str(rt) +"->"+ str(rt_int))
        config[rt]['interfaces'][rt_int].append("ip address "+str(format(host_address.pop()) + "/" + str(prefix_len)))
        config[rt]['interfaces'][rt_int].append("ipv6 address "+str(format(host_address6.pop()) + "/" + str(prefix_len6)))
        return (config, host_address, host_address6)

    config = {}
    for i in links:
        try:
            assert (len(i['endpoints']) == 2)
            link_add = link_net.pop()
            link_add6 = link_net6.pop()
            host_address = list(ipaddress.ip_network(link_add).hosts())
            host_address6 = list(ipaddress.ip_network(link_add6).hosts())
            (rt1, rt2, rt1_int, rt2_int)  = make_dict (i['endpoints'], routers)
            create_dict (rt1, config)
            create_dict (rt2, config)
            gen_config (rt1, rt1_int, host_address, host_address6, config)
            gen_config (rt2, rt2_int, host_address, host_address6, config)
        except:
            print('Error')
    return config

def config_router (nr, config, service_list):
    '''
    start with no command, then generate command from config object
    for point to point links on all the routers base on endpoints of
    clab yaml file
    '''
    cmd = []
    for service in service_list:
        for x in config[router][service].keys():
            cmd = cmd + config[router][service][x]
    results = nr.run(task=netmiko_send_config, config_commands=cmd, severity_level=logging.DEBUG)
    return results

def config_loopback (config, loopback_pool, loopback_pool6):
    for router in config.keys():
        config[router]['interfaces']['lo'] = []
        config[router]['interfaces']['lo'].append("interface lo")
        config[router]['interfaces']['lo'].append("description Loopback for "+ router)
        config[router]['interfaces']['lo'].append("ip address "+str(format(loopback_pool.pop(0))))
        config[router]['interfaces']['lo'].append("ipv6 address "+str(format(loopback_pool6.pop(0))))
    return config

def get_loopback(router, config):
    loopback = config[router]['interfaces']['lo']
    ipadd = [i for i in loopback if ipadd_regex.search(i)].pop(0)
    ipadd = ipadd_regex.search(ipadd)[0]
    return ipadd 

def get_loopback_index(router, config):
    loopback = config[router]['interfaces']['lo']
    ipadd = [i for i in loopback if ipadd_regex.search(i)].pop(0)
    ipadd = ipadd_regex.search(ipadd)[0]
    return str(int(ipadd.split('.')[3]) + 2000)

def config_ospf (config):
    for router in config.keys():
        for intf in config[router]['interfaces'].keys():
            config[router]['interfaces'][intf].append("ip ospf area 0")
            config[router]['interfaces'][intf].append("ip ospf network point-to-point")
        config[router]['protocols'] = {}
        config[router]['protocols']['ospf'] = []
        config[router]['protocols']['ospf'].append("router ospf")
        config[router]['protocols']['ospf'].append("ospf router-id "+ get_loopback(router, config))
        config[router]['protocols']['ospf'].append("log-adjacency-changes")
        config[router]['protocols']['ospf'].append("capability opaque")
        config[router]['protocols']['ospf'].append("mpls-te on")
        config[router]['protocols']['ospf'].append("mpls-te router-address "+ get_loopback(router, config))
        config[router]['protocols']['ospf'].append("segment-routing on")
        config[router]['protocols']['ospf'].append("segment-routing global-block 16000 23999")
        config[router]['protocols']['ospf'].append("segment-routing node-msd 8")
        config[router]['protocols']['ospf'].append("segment-routing prefix "+ get_loopback(router, config) + "/32 index "+ get_loopback_index(router, config))
        config[router]['protocols']['ospf'].append("router-info area")
        config[router]['protocols']['ospf'].append("exit")
    return config

def config_isis (config):
    for router in config.keys():
        for intf in config[router]['interfaces'].keys():
            config[router]['interfaces'][intf].append("ipv6 router isis SRv6")
            config[router]['interfaces'][intf].append("ip router isis SRv6")
            config[router]['interfaces'][intf].append("isis circuit-type level-1")
            config[router]['interfaces'][intf].append("isis network point-to-point")
        config[router]['protocols'] = {}
        config[router]['protocols']['isis'] = []
        config[router]['protocols']['isis'].append("ipv6 forwarding")
        config[router]['protocols']['isis'].append("router isis SRv6")
        config[router]['protocols']['isis'].append("net 49.0001.0001.0001."+ get_loopback_index(router, config) + ".00")
        config[router]['protocols']['isis'].append("is-type level-1")
        config[router]['protocols']['isis'].append("lsp-mtu 1300")
        config[router]['protocols']['isis'].append("topology ipv6-unicast")
        config[router]['protocols']['isis'].append("segment-routing on")
        config[router]['protocols']['isis'].append("segment-routing node-msd 8")
        config[router]['protocols']['isis'].append("exit")
    return config

def config_mpls_ldp (config):
    for router in config.keys():
        for intf in config[router]['interfaces'].keys():
            config[router]['interfaces'][intf].append("mpls enable")
        config[router]['protocols']['ldp'] = []
        config[router]['protocols']['ldp'].append("mpls ldp")
        config[router]['protocols']['ldp'].append("router-id "+ get_loopback(router, config))
        config[router]['protocols']['ldp'].append("address-family ipv4")
        config[router]['protocols']['ldp'].append("discovery transport-address "+ get_loopback(router, config))
        config[router]['protocols']['ldp'].append("label local advertise explicit-null")
        for intf in config[router]['interfaces'].keys():
            config[router]['protocols']['ldp'].append("interface "+ intf)
    config[router]['protocols']['ldp'].append("exit")
    return config 

def config_bgp_rr (config):
    routers = get_nodes_by_role('rr')
    for router in routers:
        config[router]['protocols']['bgp'] = []
        config[router]['protocols']['bgp'].append("router bgp "+ ASN)
        lo = ipadd_regex.search(config[router]['interfaces']['lo'][2])[0]
        config[router]['protocols']['bgp'].append("router-id "+ lo)
    return config

def init_nr ():
    logging.enabled = False 
    nr = InitNornir(
        inventory={
            "plugin": "DictInventory",
            "options": {
                "hosts": host_dict["hosts"],
                "groups": inventory_dict["groups"],
                "defaults": inventory_dict.get("defaults", {})
            },
        },
        runner={
        "plugin": "threaded",
        "options": {
            "num_workers": 50, 
            },
        },
        logging={ "enabled": False },
    )
    return nr

if __name__ == '__main__':
    check_files()
    '''
    get routers links and address assigment from lab yaml files
    '''
    (routers, endpoints) = get_endpoints(p2p_pool)
    config = config_p2p (routers, endpoints, p2p_pool, p2p_pool6)
    config = config_loopback (config, loopback_pool, loopback_pool6)
    #config = config_ospf (config)
    config = config_isis (config)
    config = config_mpls_ldp (config)
##    config = config_bgp_rr (config)
    (inventory_dict, host_dict) = get_inventory(inventory_data)
    print (json.dumps(config, indent = 4))
    nr = init_nr()
    routers_config = list(config.keys())
    for router in routers_config:
        logging.enable = False
        config_rtr = nr.filter(name=router)
        results = config_router (config_rtr, config, ['interfaces'])
        results = config_router (config_rtr, config, ['interfaces','protocols'])
        print_result(results)
