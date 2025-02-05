# Create Subscriber via Webconsole

## Install Webconsole

- If Webconsole is not yet installed, please follow the instructions on the [GitHub page](https://github.com/free5gc/webconsole).
- After successfully installing Webconsole, you can run the server using the following command:
    ```sh
    $ cd ~/free5gc/webconsole
    $ go run server.go
    ```
- (optional) If another version of free5GC was ran before, you have to delete MongoDB.
    ```sh
    $ mongo --eval "db.dropDatabase()" free5gc
    ```

## Register Subscriber Data via Webconsole

<img src="./images/login.png" alt="login" style="width:30%; height:auto; display:block; margin:auto;">

- Enter URL: `<Webconsole server's IP>:5000` in browser 
- Default credential:
    ```
    Username: admin
    Password: free5gc
    ```

### Directly Create a Subscriber on the Create Subscriber Page

- Click `SUBSCRIBERS` -> `New subscribers`
    ![](./images/create_subscriber.png)

- Edit the Subscriber's data and click `New subscribers`, here you can configure the 
    - **Network Slicing** Configuration
        - SST/SD (Slice/Service Type and Slice Differentiator)
        - **DNN** (Data Network Name) Configuration
            - AMBR (Aggregate Maximum Bit Rate)
                - Maximum total uplink/downlink bitrate limits
            - Default 5QI (5G QoS Identifier)
                - Default Quality of Service identifier
                - GBR type (5QI values: 1-4, 65-67, 71-76)
                - Non-GBR type (5QI values: 5-9, 69-70, 79-80)
            - **Flow** Configuration
                - IP Filter
                    - Source/destination IP address ranges
                    - CIDR Format (eg: "140.113.0.0/16") 
                - Precedence
                    - Priority of flow rules (lower value means higher priority)
                - 5QI (Flow-specific QoS identifier)
                    - Non-GBR flows: Best effort traffic, no bandwidth guarantee
                    - GBR flows: Guaranteed bit rate for specific services
                - Uplink GBR/MBR (Guaranteed/Maximum Bit Rate)
                    - Applicable for GBR 5QI flows
                - Downlink GBR/MBR (Guaranteed/Maximum Bit Rate)
                    - Applicable for GBR 5QI flows

- You can refer to this sample configuration
    | ![](./images/subscriberData1.png) | ![](./images/subscriberData2.png) |
    |-----------------------------------|-----------------------------------|
    | ![](./images/subscriberData3.png) | ![](./images/flow_rules.png)     |

- After successfully inserting the data, you can check the `Subscribers` to verify it.
    ![](./images/create_subscriber2.png)