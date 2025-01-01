<!-- include start from rpki/protocol-common-config.xml.i -->
<tagNode name="cache">
  <properties>
    <help>RPKI cache server address</help>
    <valueHelp>
      <format>ipv4</format>
      <description>IP address of RPKI server</description>
    </valueHelp>
    <valueHelp>
      <format>ipv6</format>
      <description>IPv6 address of RPKI server</description>
    </valueHelp>
    <valueHelp>
      <format>hostname</format>
      <description>Fully qualified domain name of RPKI server</description>
    </valueHelp>
    <constraint>
      <validator name="ip-address"/>
      <validator name="fqdn"/>
    </constraint>
  </properties>
  <children>
    #include <include/port-number.xml.i>
    <leafNode name="preference">
      <properties>
        <help>Preference of the cache server</help>
        <valueHelp>
          <format>u32:1-255</format>
          <description>Preference of the cache server</description>
        </valueHelp>
        <constraint>
          <validator name="numeric" argument="--range 1-255"/>
        </constraint>
      </properties>
    </leafNode>
    <node name="ssh">
      <properties>
        <help>RPKI SSH connection settings</help>
      </properties>
      <children>
        #include <include/pki/openssh-key.xml.i>
        #include <include/generic-username.xml.i>
      </children>
    </node>
  </children>
</tagNode>
<leafNode name="expire-interval">
  <properties>
    <help>Interval to wait before expiring the cache</help>
    <valueHelp>
      <format>u32:600-172800</format>
      <description>Interval in seconds</description>
    </valueHelp>
    <constraint>
      <validator name="numeric" argument="--range 600-172800"/>
    </constraint>
  </properties>
  <defaultValue>7200</defaultValue>
</leafNode>
<leafNode name="polling-period">
  <properties>
    <help>Cache polling interval</help>
    <valueHelp>
      <format>u32:1-86400</format>
      <description>Interval in seconds</description>
    </valueHelp>
    <constraint>
      <validator name="numeric" argument="--range 1-86400"/>
    </constraint>
  </properties>
  <defaultValue>300</defaultValue>
</leafNode>
<leafNode name="retry-interval">
  <properties>
    <help>Retry interval to connect to the cache server</help>
    <valueHelp>
      <format>u32:1-7200</format>
      <description>Interval in seconds</description>
    </valueHelp>
    <constraint>
      <validator name="numeric" argument="--range 1-7200"/>
    </constraint>
  </properties>
  <defaultValue>600</defaultValue>
</leafNode>
<!-- include end -->
