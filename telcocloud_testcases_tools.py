#!/usr/bin/python

__author__ = "Bassem Aly"
__EMAIL__ = "basim.alyy@gmail.com"

from vnc_api.vnc_api import *
from cfgm_common.exceptions import BadRequest, RefsExistError
from keystoneauth1.identity import v3
from keystoneauth1 import session
from keystoneclient.v3 import client
from novaclient import client as nclient
from glanceclient import client as gclient
from neutronclient.neutron import client as neuclient
from jnpr.junos import Device
from jnpr.junos.exception import *
import collections
import uuid
import sys
import netaddr
from pprint import pprint
import warnings

warnings.filterwarnings(action='ignore', module='.*paramiko.*')


dc_parameters = {

    "API_SERVER": "CONTRAIL_IP_ADDRESS",
    "AUTH_URL": "OPENSTACK_AUTH_URL",
    "OVERCLOUD_PASSWORD": "OVERCLOUD_PASSWORD",
    "AUTH_HOST": "KEYSTONE_AUTH_ADDRESS",
    "SDN_GATEWAYS": {
        "host": "SDN_GATEWAY_IP_ADDRESS",
        "nc_username": "SDN_GATEWAY_USERNASME",
        "nc_password": "SDN_GATEWAY_PASSWORD",
        "fabric_gateway_name": "SDN_GATEWAY_HOSTNAME"
    },
    "DEFAULT_SECURITY_GROUP": 'DEFAULT_SEC_GROUP_ID'

}

environment = dc_parameters

locals().update(environment)

class contrail_utils(object):
    def __init__(self, ):
        pass

    def open_connection_to_contrail(self, ):
        self.username = "admin"
        self.password = OVERCLOUD_PASSWORD
        self.tenant_name = "admin"
        self.api_server_host = API_SERVER
        self.auth_host = AUTH_HOST
        try:
            self.vnc_lib = VncApi(username=self.username,
                                  password=self.password,
                                  tenant_name=self.tenant_name,
                                  api_server_host=self.api_server_host,
                                  auth_host=self.auth_host)
        except:
            print("Cannot connect to API server, please check your credentials, Exiting")
            exit(1)

    def create_new_virtual_network(self, vn_name, prefix, rt="", project="admin", gateway="", physnet="", seg_id="", ):
        self.project = project
        self.name = vn_name
        self.prefix = prefix
        self.gateway = gateway if gateway else netaddr.IPNetwork(prefix)[1]
        self.rt = [rt] if rt else []
        self.physnet = physnet if physnet else ""
        self.seg_id = seg_id if seg_id else ""
        self.network_data = None
        try:
            self.vn_tenant_obj = self.vnc_lib.project_read(fq_name=['default-domain', '{0}'.format(project)])
            self.ipam = self.vnc_lib.network_ipam_read(
                fq_name=['default-domain', 'default-project', 'default-network-ipam'])

        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))

        except Exception as e:
            print("Cannot read basic info, Exiting")
            print(e)
            exit(1)

        try:
            self.network_prefix = netaddr.IPNetwork(self.prefix)
        except (netaddr.core.AddrFormatError, ValueError):
            raise ValueError("Network ({0}) is not in CIDR presentation format, exiting".format(self.network_prefix))

        self.network_data = VirtualNetwork(name=self.name, parent_obj=self.vn_tenant_obj)

        self.network_subnet = SubnetType(ip_prefix=str(self.network_prefix.ip),
                                         ip_prefix_len=int(self.network_prefix.prefixlen))

        self.ipam_subnet = IpamSubnetType(
            subnet=self.network_subnet,
            default_gateway=str(self.gateway))

        self.network_data.set_network_ipam(ref_obj=self.ipam, ref_data=VnSubnetsType([self.ipam_subnet]))

        if self.rt:
            self.network_data.set_route_target_list(RouteTargetList(route_target=self.rt))

        if self.physnet and self.seg_id:
            self.network_data.set_provider_properties(
                ProviderDetails(segmentation_id=self.seg_id, physical_network=self.physnet))

        try:
            self.vn = self.vnc_lib.virtual_network_create(self.network_data)

        except RefsExistError:
            print("Network is already exist, trying to update")

            try:
                self.vn = self.vnc_lib.virtual_network_update(self.network_data)

            except BadRequest as e:
                print("Request is malformed, please check: {0}".format(e))
            except Exception as e:
                print(e)
            pass
        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))
        except Exception as e:
            print(e)
        return self.vn

    def create_new_physical_and_bgp_router(self, router_name, mgmt_ip, username, password, asn=64512):

        self.router_name = router_name
        self.mgmt_ip = mgmt_ip
        self.username = username
        self.password = password
        self.asn = asn
        self.rt_inst_obj = self.vnc_lib.routing_instance_read(
            fq_name=['default-domain', 'default-project',
                     'ip-fabric', '__default__'])
        self.bgp_router_data = BgpRouter(self.router_name, parent_obj=self.get_ip_fabric_ri_obj())
        params = BgpRouterParams()
        params.address = self.mgmt_ip
        params.address_families = AddressFamilies(['route-target', 'inet-vpn', 'e-vpn',
                                                   'inet6-vpn'])
        params.autonomous_system = self.asn
        params.vendor = 'juniper'
        params.identifier = self.mgmt_ip
        self.bgp_router_data.set_bgp_router_parameters(params)

        try:
            self.vnc_lib.bgp_router_create(self.bgp_router_data)

        except RefsExistError:
            print("BGP Router is already exist, trying to update")
            self.vnc_lib.bgp_router_update(self.bgp_router_data)
            pass

        self.physical_router_data = PhysicalRouter(self.router_name)
        self.physical_router_data.physical_router_management_ip = self.mgmt_ip
        self.physical_router_data.physical_router_vendor_name = 'juniper'
        self.physical_router_data.physical_router_product_name = 'mx'
        self.physical_router_data.physical_router_vnc_managed = True
        user_creds_data = UserCredentials(self.username, self.password)

        try:
            self.physical_router_data.set_physical_router_user_credentials(user_creds_data)
            self.physical_router_data.set_bgp_router(self.bgp_router_data)
            self.physical_router_id = self.vnc_lib.physical_router_create(self.physical_router_data)

        except RefsExistError:
            print("Router is already exist, trying to update")
            self.vnc_lib.physical_router_update(self.physical_router_data)
            pass
        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))

        except Exception as e:
            print("e")

        def get_ip_fabric_ri_obj(self):
            self.rt_inst_obj = self.vnc_lib.routing_instance_read(
                fq_name=['default-domain', 'default-project',
                         'ip-fabric', '__default__'])

            return self.rt_inst_obj



    def create_port_over_existing_network(self, virtual_port_name, vn_name, fixed_ip="", fixed_mac="",
                                          policy_enabled=False,
                                          sriov=False, project="admin"):

        self.project = project
        self.virtual_port_name = virtual_port_name
        self.vn_name = vn_name
        self.fixed_ip = fixed_ip
        self.fixed_mac = fixed_mac
        self.policy_enabled = policy_enabled
        self.sriov = sriov

        self.port_data = None

        try:
            # print(vnc_lib.projects_list())
            self.vn_tenant_obj = self.vnc_lib.project_read(fq_name=['default-domain', '{0}'.format(self.project)])
            self.vn_obj = self.vnc_lib.virtual_network_read(
                fq_name=['default-domain', '{0}'.format(self.project), '{0}'.format(self.vn_name)])

        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))
        except Exception as e:
            print("Cannot read basic info to process, Exiting")
            print(e)
            exit(1)

        # Checking
        if self.fixed_ip:
            try:
                self.fixed_ip = netaddr.IPNetwork(self.fixed_ip)
            except (netaddr.core.AddrFormatError, ValueError):
                raise ValueError(
                    "Fixed IP ({0}) is not in IP representation format, exiting".format(self.fixed_ip))

        if self.fixed_mac:
            try:
                self.fixed_mac = netaddr.EUI(self.fixed_mac)
            except (netaddr.core.AddrFormatError, ValueError):
                raise ValueError("MAC ({0}) is not in standard 48 format, exiting".format(self.fixed_mac))

        self.port_data = VirtualMachineInterface(name=self.virtual_port_name, parent_obj=self.vn_tenant_obj)
        self.port_data.set_display_name(self.virtual_port_name)
        self.port_data.name = self.virtual_port_name
        pprint(self.port_data.name)
        self.port_data.set_virtual_machine_interface_disable_policy(self.policy_enabled)


        if self.fixed_mac:
            self.fixed_mac.dialect = netaddr.mac_unix
            self.port_data.set_virtual_machine_interface_mac_addresses(MacAddressesType([str(self.fixed_mac)]))

        self.port_data.add_virtual_network(self.vn_obj)

        if self.sriov:
            if "segmentation_id" in str(self.vn_obj.get_provider_properties()):

                self.port_data.set_virtual_machine_interface_bindings(
                    KeyValuePairs([KeyValuePair(key="vnic_type", value="direct")]))

            else:
                raise ValueError(
                    "Passed Network uuid: ({0}) is not provider network, exiting".format(
                        self.vn_obj.get_fq_name_str()))

        else:
            self.port_data.set_virtual_machine_interface_bindings(
                KeyValuePairs([KeyValuePair(key="vnic_type", value="normal")]))

        try:
            self.vmi_obj = self.vnc_lib.virtual_machine_interface_create(self.port_data)

            # This should happen after creation
            if self.fixed_ip:
                self.fixed_ip = self.fixed_ip.ip.__str__()

                print("Reading The VMI")
                self.vmi_obj = self.vnc_lib.virtual_machine_interface_read(
                    fq_name=self.port_data.get_fq_name())

                iip_obj = InstanceIp(name=str(uuid.uuid4()), instance_ip_family='v4')

                print("setting fixed IP")
                iip_obj.set_instance_ip_address(str(self.fixed_ip))
                iip_obj.set_instance_ip_family('v4')

                iip_obj.set_virtual_machine_interface(self.vmi_obj)
                iip_obj.set_virtual_network(self.vn_obj)
                self.vnc_lib.instance_ip_create(iip_obj)


        except RefsExistError:
            print("Port is already exist, trying to update")

            try:
                self.vnc_lib.virtual_machine_interface_update(self.port_data)
                self.vmi_obj = self.vnc_lib.virtual_machine_interface_read(
                    fq_name=['default-domain', '{0}'.format(self.project), '{0}'.format(self.virtual_port_name)])

            except BadRequest as e:
                print("Request is malformed, please check: {0}".format(e))

            except Exception as e:
                print(e)

            pass

        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))

        except Exception as e:
            print(e)

        print(self.vmi_obj._uuid)
        return self.vmi_obj._uuid

    def extend_virtual_network_to_fabric_gateway(self, virtual_network_name):
        self.fabric_gateway_name = environment["SDN_GATEWAYS"]['fabric_gateway_name']
        self.virtual_network_name = virtual_network_name

        try:
            self.fabric_gateway_obj = self.vnc_lib.physical_router_read(
                fq_name=[u'default-global-system-config', u'{0}'.format(self.fabric_gateway_name)])

            self.extended_vn_obj = self.vnc_lib.virtual_network_read(
                fq_name=['default-domain', '{0}'.format(self.project), '{0}'.format(self.virtual_network_name)])

        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))
        except Exception as e:
            print("Cannot read basic info to process, Exiting")
            print(e)
            exit(1)

        try:
            self.fabric_gateway_obj.add_virtual_network(self.extended_vn_obj)

            self.vnc_lib.physical_router_update(self.extended_vn_obj)

        except Exception as e:
            pprint("**ERROR {0}".format(e))

    def create_tagged_port_over_existing_fabric_node(self, physical_router_name, physical_port_name, vn_name, vlan):

        self.physical_router_name = physical_router_name
        self.physical_port_name = physical_port_name
        self.vlan = vlan
        self.vn_name = vn_name

        try:
            physical_router_obj = self.vnc_lib.physical_router_read(
                fq_name=['default-global-system-config', self.physical_router_name])

            bgp_router_obj = self.vnc_lib.bgp_router_read(
                fq_name=['default-global-system-config', self.physical_router_name])
            vn_obj = self.vnc_lib.virtual_network_read(
                fq_name=['default-domain', '{0}'.format(self.project), '{0}'.format(self.vn_name)])

        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))
        except Exception as e:
            print("Cannot read basic info to process, Exiting")
            print(e)
            exit(1)

        try:
            physical_interface = self.vnc_lib.physical_interface_read(
                fq_name=['default-global-system-config', self.physical_router_name, self.physical_port_name])
        except NoIdError:
            physical_interface = PhysicalInterface(self.physical_port_name, parent_obj=physical_router_obj)
            pi_id = self.vnc_lib.physical_interface_create(physical_interface)
            pass

        try:
            logical_interface_object = self.vnc_lib.logical_interface_read(
                fq_name=[u'default-global-system-config', self.physical_router_name, self.physical_port_name,
                         self.physical_port_name + "." + self.vlan])
        except NoIdError:
            logical_interface_object = LogicalInterface(self.physical_port_name + "." + self.vlan,
                                                        parent_obj=physical_interface)
            logical_interface_object.vlan_tag = self.vlan
            logical_interface_object.set_virtual_machine_interface(self.vmi_obj)
            li_id = self.vnc_lib.logical_interface_create(logical_interface_object)

    def delete_virtual_network_port(self, virtual_port_name, project="admin"):

        try:
            vmi_obj = self.vnc_lib.virtual_machine_interface_read(
                fq_name=['default-domain', '{0}'.format(project), '{0}'.format(virtual_port_name)])

        except:
            print("Port is not exist")
            pass

        try:
            self.vnc_lib.virtual_machine_interface_delete(
                fq_name=['default-domain', '{0}'.format(project), '{0}'.format(virtual_port_name)])
        except RefsExistError:
            if isinstance(vmi_obj.get_instance_ip_back_refs(), collections.Iterable):
                for iip in vmi_obj.get_instance_ip_back_refs():
                    try:
                        pprint("LOG: Releasing the IP address from the port")
                        self.vnc_lib.instance_ip_delete(id=iip['uuid'])
                    except:
                        pass
                self.vnc_lib.virtual_machine_interface_delete(
                    fq_name=['default-domain', '{0}'.format(project), '{0}'.format(virtual_port_name)])

    def delete_physical_and_bgp_router(self, physical_router_name, ):  # should we delete the physical intfs first?

        try:
            self.vnc_lib.physical_router_read(
                fq_name=['default-global-system-config', physical_router_name])

            bgp_router_obj = self.vnc_lib.bgp_router_read(
                fq_name=['default-global-system-config', physical_router_name])

        except:
            print("Routers is not exist")
            pass

        self.vnc_lib.physical_router_delete(
            fq_name=['default-global-system-config', physical_router_name])
        self.vnc_lib.bgp_router_delete(
            fq_name=['default-global-system-config', physical_router_name])

    def delete_virtuaL_network_from_fabric_gateway(self, virtual_network_name):
        self.fabric_gateway_name = environment["SDN_GATEWAYS"]['fabric_gateway_name']
        self.virtual_network_name = virtual_network_name

        try:
            self.fabric_gateway_obj = self.vnc_lib.physical_router_read(
                fq_name=[u'default-global-system-config', u'{0}'.format(self.fabric_gateway_name)])

            self.extended_vn_obj = self.vnc_lib.virtual_network_read(
                fq_name=['default-domain', '{0}'.format(self.project), '{0}'.format(self.virtual_network_name)])

        except BadRequest as e:
            print("Request is malformed, please check: {0}".format(e))
        except Exception as e:
            print("Cannot read basic info to process, Exiting")
            print(e)
            exit(1)

        try:
            self.fabric_gateway_obj.del_virtual_network(self.extended_vn_obj)

            self.vnc_lib.physical_router_update(self.extended_vn_obj)

        except Exception as e:
            pprint("**ERROR {0}".format(e))

    def delete_virtual_network(self, virtual_network, project="admin"):

        try:
            self.vnc_lib.virtual_network_read(
                fq_name=['default-domain', '{0}'.format(project), '{0}'.format(virtual_network)])

        except:
            print("Network is not exist")
            pass

        self.vnc_lib.virtual_network_delete(
            fq_name=['default-domain', '{0}'.format(project), '{0}'.format(virtual_network)])


class openstack_utils(object):  # should contains the open/SetUp/TearDown
    def __init__(self, admin=True):
        self.admin = admin

    def open_connection_to_openstack(self):
        if self.admin:
            print("Generating Admin Token")
            self.auth = v3.Password(auth_url=AUTH_URL,
                                    username="admin",
                                    password=OVERCLOUD_PASSWORD,
                                    project_name="admin",
                                    user_domain_name="Default",
                                    project_domain_name="Default")

            # print(self.auth)
        print("Generating Plugins")
        self.sess = session.Session(auth=self.auth, verify=False)
        print self.sess
        self.keystone = client.Client(session=self.sess, include_metadata=True)
        self.nova = nclient.Client(2.1, session=self.sess, http_log_debug=True)
        # self.nova = nvclient.Client(2.1, session=self.sess, http_log_debug=True)
        self.glance = gclient.Client(2, session=self.sess)
        self.neutron = neuclient.Client(2, session=self.sess)
        self.token = self.auth.get_token(self.sess)

    def create_flavor(self, flavor_name="ATDD_TESTING_FLAVOR", ram=6144, vcpus=6, disk=15, dpdk=False):

        self.flavor_name = flavor_name
        self.exist = False
        self.ram = ram
        self.vcpus = vcpus
        self.disk = disk
        self.dpdk = dpdk

        self.flavor_list = self.nova.flavors.list()

        for flavor in self.flavor_list:
            if flavor.name == self.flavor_name:
                print("Flavor is already exist")
                self.flavor_data = flavor
                self.exist = True

        if not self.exist:
            self.flavor_data = self.nova.flavors.create(name=self.flavor_name, ram=self.ram, vcpus=self.vcpus,
                                                        disk=self.disk, flavorid="auto")

            if self.dpdk:
                metadata = {
                    "hw:cpu_policy": "dedicated",
                    "hw:cpu_thread_policy": "prefer",
                    "hw:mem_page_size": "1048576",

                }

                self.flavor_data.set_keys(metadata)

    def get_image_id_from_openstack_glance(self, image_name):
        self.image_name = image_name
        self.image_data = self.nova.glance.find_image(self.image_name)

    def create_virtual_machine(self, server_name, ports, az="nova"):  # pass userdata

        self.exist = False
        self.server_name = server_name
        self.ports = ports
        self.az = az

        # self.nics = [{'port-id': ports._uuid}] #run within python, otherwise they should be strings
        self.nics = [{'port-id': ports}]

        self.servers_list = self.nova.servers.list()
        for server in self.servers_list:
            if server.name == self.server_name:
                print("server name is already exist")
                self.server = server
                self.exist = True
                self.vnf_obj_id = self.nova.servers.get(server.id)
                break  # no need to continue

        if not self.exist:
            # secgroup = self.nova.security_groups.find(name="default")
            vnf_obj = self.nova.servers.create(name=self.server_name,
                                               image=self.image_data.id,
                                               flavor=self.flavor_data.id,
                                               nics=self.nics,
                                               availability_zone=self.az,
                                               config_drive=True,
                                               # security_groups=['ec62dcd2-91b1-478b-93b6-d39466ae40fb']
                                               # security_groups=[{'id': 'ec62dcd2-91b1-478b-93b6-d39466ae40fb'}]
                                               )
            status = vnf_obj.status
            while status == 'BUILD':
                time.sleep(5)
                self.vnf_obj_id = self.nova.servers.get(vnf_obj.id)
                status = self.vnf_obj_id.status
                print "status: {0}".format(status)

        # Add the admin default security groups
        # self.nova.servers.add_security_group(self.vnf_obj_id, DEFAULT_SECURITY_GROUP)
        return self.vnf_obj_id

    def associate_default_security_group_to_virtual_machine(self, vnf_obj_id):
        self.nova.servers.add_security_group(vnf_obj_id, DEFAULT_SECURITY_GROUP)




    def get_virtual_machine_console_url(self, vnf_obj_id):

        console_type = "novnc"

        url = self.nova.servers.get_console_url(vnf_obj_id, console_type)
        return url['console']['url']

    def get_virtual_machine_console_output(self, vnf_obj_id, console_length):

        return self.nova.servers.get_console_output(vnf_obj_id, console_length)

    def delete_flavor(self, flavor_name):

        flavor = self.nova.servers.find(name=flavor_name)

        if flavor:
            flavor.delete()

    def delete_virtual_machine(self, server_name):
        server = self.nova.servers.find(name=server_name)
        if server:
            server.delete()


class juniper_fabric_utils(object):

    def __init__(self):  # should we read it from environment file?
        self.dev = Device(host=environment["SDN_GATEWAYS"]['host'],
                          user=environment["SDN_GATEWAYS"]['nc_username'],
                          password=environment["SDN_GATEWAYS"]['nc_password'],
                          gather_facts=True,
                          port=22)

    def open_the_connection(self):

        try:
            print("Open connection to device: {0}".format(environment["SDN_GATEWAYS"]['host']))
            self.dev.open()

        except ConnectRefusedError:
            print("Connection refused to device: {0}".format(environment["SDN_GATEWAYS"]['host']),
                  )
            exit()
        except ConnectTimeoutError:
            print("Connection timed out to device: {0}".format(environment["SDN_GATEWAYS"]['host']),
                  )
            exit()
        except ConnectAuthError:
            print("Connection creds is not correct to device: {0}".format(environment["SDN_GATEWAYS"]['host']),
                  )
            exit()
        except Exception as Error:
            print("Unable to connect to device: {0} due to: ".format(environment["SDN_GATEWAYS"]['host']),
                  )
            exit()
        print("Connection status: {0}".format(str(self.dev.connected)))

        if not self.dev.connected:
            self.dev = False

    def verify_route_is_exist_in_fabric_node(self, route):
        self.route = route
        self.is_exist = False
        self.table = None
        self.route_info = self.dev.rpc.get_route_information(normalize=True, destination=self.route)

        if self.route_info is not None:
            for item in self.route_info.findall("route-table/rt"):
                if item.findtext("rt-destination") and item.findtext("rt-destination") != "0.0.0.0":
                    self.is_exist = True
                    self.table = item.findtext("../table-name")
                    print(self.table)
                    return self.is_exist
                    # break  # no need to get all tables

    def ping_virtual_machine_from_fabric_node(self, route, table=""):
        self.route = route
        self.table = table
        self.ping_success = None

        if self.table:
            self.ping_response = self.dev.rpc.ping(normalize=True, host=self.route, count="5",
                                                   routing_instance=self.table)

        else:
            self.ping_response = self.dev.rpc.ping(normalize=True, host=self.route, count="5")

        try:
            if self.ping_response.find("ping-failure").tag == "ping-failure":
                self.ping_success = False
                raise

        except:
            pass

        try:
            if self.ping_response.find("ping-success").tag == "ping-success":
                self.ping_success = True
        except:
            pass

        return self.ping_success

    def close_the_connection(self):
        if self.dev:
            print("closing the connection to device")
            self.dev.close()
