import re
import time
import json
import logging
import argparse
import threading
from collections import OrderedDict

import paho.mqtt.client as mqtt

from .device import DahuaDevice


logging.basicConfig(format='%(asctime)s %(levelname)s: %(message)s', level=logging.INFO)
log = logging.getLogger('__name__')


DISCOVERY_PREFIX = 'homeassistant'
NODE_ID = 'dahua_nvr'
SET_RE = re.compile(rf'{DISCOVERY_PREFIX}/switch/{NODE_ID}/cam(\d+)/set')
OFF_SUFFIX = '_OFF_'
DEVICE_INFO = {
    'identifiers': [
        'dahua_nvr',
    ],
    'manufacturer': 'Community',
    'model': 'Dahua NVR',
    'name': 'Dahua NVR',
}

state_changed_event = threading.Event()
device_lock = threading.Lock()
mqtt_lock = threading.Lock()


def read_state(device: DahuaDevice):
    with device_lock:
        cameras = device.secure_request('LogicDeviceManager.secGetCameraAll', None)['params']['camera']
    cameras = filter(lambda c: c['Type'] == 'Remote', cameras)
    cameras_dict = OrderedDict((c['UniqueChannel'], c) for c in cameras if c.get('Enable'))

    with device_lock:
        states = device.request('LogicDeviceManager.getCameraState', {'uniqueChannels': [-1]})['params']['states']
    for s in states:
        cam = cameras_dict.get(s['channel'])
        if cam:
            cam['_state'] = s['connectionState'] == 'Connected'

    for cam in cameras_dict.values():
        channel0 = cam['UniqueChannel']
        channel1 = channel0 + 1
        cam['_name'] = f'cam{channel1}'

    # import pprint
    # pprint.pprint(cameras)
    # pprint.pprint(states)
    # pprint.pprint(cameras_dict)

    return cameras_dict


def publish_config(client: mqtt.Client, state):
    for cam in state.values():
        cam_name = cam['_name']
        mqtt_prefix = f'{DISCOVERY_PREFIX}/switch/{NODE_ID}/{cam_name}'

        unique_id = f'{NODE_ID}_{cam_name}'
        ip = cam['DeviceInfo']['Address']

        entity_config = {
            'unique_id': unique_id,
            'name': cam_name.upper(),
            'command_topic': f'{mqtt_prefix}/set',
            'state_topic': f'{mqtt_prefix}/state',
            'device': DEVICE_INFO,
            'icon': 'mdi:video',
        }

        if ip:
            entity_config['device']['configuration_url'] = f'http://{ip}/'

        with mqtt_lock:
            client.publish(f'{mqtt_prefix}/config', json.dumps(entity_config), qos=1)
        log.info('%s config published', cam_name)


def publish_state(client: mqtt.Client, state):
    for cam in state.values():
        cam_name = cam['_name']
        mqtt_prefix = f'{DISCOVERY_PREFIX}/switch/{NODE_ID}/{cam_name}'

        state_str = 'ON' if cam['_state'] else 'OFF'

        with mqtt_lock:
            client.publish(f'{mqtt_prefix}/state', state_str, qos=1)
        log.info('%s state published', cam_name)


def on_connect(client: mqtt.Client, device: DahuaDevice, flags, reason_code, properties):
    state = read_state(device)
    publish_config(client, state)
    publish_state(client, state)

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    with mqtt_lock:
        client.subscribe(f'{DISCOVERY_PREFIX}/switch/{NODE_ID}/+/set')


def on_message(client: mqtt.Client, device: DahuaDevice, msg: mqtt.MQTTMessage):
    match = SET_RE.match(msg.topic)
    if not match:
        log.error('Got invalid MQTT topic: %s', msg.topic)
        return

    new_state_b = msg.payload
    if new_state_b == b'ON':
        new_state = True
    elif new_state_b == b'OFF':
        new_state = False
    else:
        log.error('Got invalid state: %s', new_state_b)
        return

    channel1 = int(match.group(1))
    channel0 = channel1 - 1

    state = read_state(device)
    cam = state[channel0]
    cam_name = cam['_name']

    username = cam['DeviceInfo']['UserName']
    current_state = not username.endswith(OFF_SUFFIX)

    if new_state == current_state:
        publish_state(client, state)
        return

    if new_state:
        username = username.removesuffix(OFF_SUFFIX)
    else:
        username += OFF_SUFFIX
    cam['DeviceInfo']['UserName'] = username

    # unknown field added on `LogicDeviceManager.secSetCamera`
    cam['DeviceInfo']['VideoInputChannels'] = None

    with device_lock:
        device.secure_request('LogicDeviceManager.secSetCamera', {'cameras': [cam]})
    if new_state:
        log.info('%s turned on', cam_name)
    else:
        log.info('%s turned off', cam_name)

    cam['_state'] = new_state
    publish_state(client, state)
    state_changed_event.set()


def on_message_protected(*args, **kwargs):
    try:
        return on_message(*args, **kwargs)
    except Exception:
        log.exception('Got error during message handling')


class UpdateThread(threading.Thread):
    def __init__(self,
                 client: mqtt.Client,
                 device: DahuaDevice,
                 update_interval: float = 10,
                 config_update_every: int = 10):
        super().__init__(daemon=True)
        self.client = client
        self.device = device
        self.update_interval = update_interval
        self.config_update_every = config_update_every

    def run(self):
        counter = 0

        while True:
            if state_changed_event.wait(timeout=self.update_interval):
                state_changed_event.clear()
                log.info('State changed, will wait for 10 seconds and refresh state from NVR')
                # if woken by event, give some time for NVR to connect to new camera
                time.sleep(10)
            else:
                log.info('Refreshing state from NVR by timer')

            counter += 1
            if self.client.is_connected:
                try:
                    state = read_state(self.device)
                    publish_state(self.client, state)
                    if counter % self.config_update_every == 0:
                        # refresh config every 10th update
                        log.info('Also refreshing device config')
                        publish_config(self.client, state)
                except Exception:
                    log.exception('Got error while updating state')


def main():
    arg_parser = argparse.ArgumentParser()
    arg_parser.add_argument('--mqtt-host', required=True)
    arg_parser.add_argument('--mqtt-port', type=int, default=1883)
    arg_parser.add_argument('--mqtt-username', required=True)
    arg_parser.add_argument('--mqtt-password', required=True)
    arg_parser.add_argument('--dahua-host', required=True)
    arg_parser.add_argument('--dahua-username', required=True)
    arg_parser.add_argument('--dahua-password', required=True)
    arg_parser.add_argument('--update-interval', type=int, default=10)
    arg_parser.add_argument('--config-update-every', type=int, default=10)

    args = arg_parser.parse_args()

    DEVICE_INFO['configuration_url'] = f'http://{args.dahua_host}/'

    log.info('Connecting to Dahua NVR...')
    device = DahuaDevice(args.dahua_host)
    with device_lock:
        device.login(args.dahua_username, args.dahua_password)

    log.info('Connecting to MQTT server...')
    mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    with mqtt_lock:
        mqttc.user_data_set(device)
        mqttc.on_connect = on_connect
        mqttc.on_message = on_message_protected
        mqttc.username_pw_set(args.mqtt_username, args.mqtt_password)
        mqttc.connect(args.mqtt_host, args.mqtt_port)

    log.info('Starting update thread...')
    update_thread = UpdateThread(mqttc, device, args.update_interval, args.config_update_every)
    update_thread.start()

    log.info('Running...')
    # Blocking call that processes network traffic, dispatches callbacks and
    # handles reconnecting.
    # Other loop*() functions are available that give a threaded interface and a
    # manual interface.
    mqttc.loop_forever()


if __name__ == '__main__':
    main()
