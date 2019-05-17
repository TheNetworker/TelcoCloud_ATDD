# TelcoCloud Automated Testing
A set of keywords &amp; tools that could be used to automate the testing in Telco cloud environment with Robotframework.
![image](plan.png)


## How to run
Visit the following blog post for more details

https://basimaly.wordpress.com/2019/05/17/automated-testing-in-telco-cloud-using-robot-framework/

modify the credentials in pybot file
```python
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
```
Create the pod
```shell
/usr/local/bin/robot \
--pythonpath Scripts/TelcoCloud_Testing\
--outputdir Scripts/TelcoCloud_Testing\
-l DEBUG \
--include create_pod \ 
TelcoCloud_Testing/test_basic_vnf_connectivity.robot
```


Delete the pod
```shell
/usr/local/bin/robot \
--pythonpath Scripts/TelcoCloud_Testing\
--outputdir Scripts/TelcoCloud_Testing\
-l DEBUG \
--include delete_pod \ 
TelcoCloud_Testing/test_basic_vnf_connectivity.robot
```
