*** Settings ***
Library  telcocloud_testcases_tools.contrail_utils
Library  telcocloud_testcases_tools.openstack_utils
Library  telcocloud_testcases_tools.juniper_fabric_utils
Test Setup     open the connection
Test Teardown  close the connection

*** Variables ***

#Virtual Network Section
${vn_name}  test_from_robot
${vn_prefix}  10.200.220.0/28


#Port Section
${port_name}  test_port_from_robot
${port_ip}  10.200.220.10
${port_mac_address}  02:fa:fa:ba:ba:ba

#VM Section
${vm_name}  ATDD_TESTING_SRV01
${vm_azone}  nova:dpdk_compute01


#Fabric section
${vn_route_target}  target:65000:5000


${vm_routing_instance}  TelcoCloud_MGMT_VRF



*** Test Cases ***

Create New Virtio Network using SDN controller
    [Tags]  create_pod
    [Setup]  open connection to contrail
    create new virtual network  vn_name=${vn_name}   prefix=${vn_prefix}   rt=${vn_route_target}


Create New Port over existing virtual network
    [Tags]  create_pod
    [Setup]  open connection to contrail
    ${port_uuid} =  create port over existing network  ${port_name}  ${vn_name}  ${port_ip}
    Set Global Variable   ${port_uuid}

Create Virtual Machine in openstack
    [Tags]  create_pod
    [Setup]  open connection to openstack
    create flavor
    get image id from openstack glance  centos-dpdk
    ${vm_uuid} =  create virtual machine  ${vm_name}  ${port_uuid}  ${vm_azone}
    Set Global Variable   ${vm_uuid}
    ${console_url} =  get virtual machine console url  ${vm_uuid}
    log to console   ${console_url}

Associate Default Security Group to created VNF
    [Tags]  create_pod
    [Setup]  open connection to openstack
    associate default security group to virtual machine  ${vm_uuid}


Wait until the virtual machine complete boot process
    [tags]  create_pod
    Sleep  1m


Wait until the SDN controller announce the service prefix
    [tags]  create_pod
    Sleep  30s



Check if the route learnt in the fabric (Control Plane Check)
    [tags]  create_pod
    [Setup]  open the connection
    ${ip_with_subnet_mask}=  Catenate  ${port_ip}/32
    ${route_is_exist} =  verify route is exist in fabric node    ${ip_with_subnet_mask}
    should be true  ${route_is_exist}
    [Teardown]  close the connection


Check if the route is pingable from the fabric (Forwarding Plane Check)
    [Tags]  create_pod
    [Setup]  open the connection
    ${ping_result} =  ping virtual machine from fabric node   ${port_ip}  table=${vm_routing_instance}
    should be true  ${ping_result}
    [Teardown]  close the connection



#CleanUp/TearDown

Delete the created virtual machine
    [Tags]  delete_pod
    [Setup]  open connection to openstack
    delete virtual machine    ${vm_name}

Delete the created port
    [Tags]  delete_pod
    [Setup]  open connection to contrail
    delete virtual network port    ${port_name}


Delete the the created virtual network
    [Tags]  delete_pod
    [Setup]  open connection to contrail
    delete virtual network    ${vn_name}


