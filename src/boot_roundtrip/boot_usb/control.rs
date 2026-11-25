use crate::transport::{LocalFeatureTransport, TransportError, TransportFailure};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Setup {
    pub request_type: u8,
    pub request: u8,
    pub value: u16,
    pub index: u16,
    pub length: u16,
}
pub(super) const DESCRIPTOR: Setup = Setup {
    request_type: 0x81,
    request: 6,
    value: 0x2200,
    index: 0,
    length: 24,
};
pub(super) const SET: Setup = Setup {
    request_type: 0x21,
    request: 9,
    value: 0x0307,
    index: 0,
    length: 64,
};
pub(super) const GET: Setup = Setup {
    request_type: 0xa1,
    request: 1,
    value: 0x0307,
    index: 0,
    length: 64,
};
pub(super) trait ControlIo {
    fn read(&mut self, setup: Setup, buffer: &mut [u8]) -> Result<usize, String>;
    fn write(&mut self, setup: Setup, buffer: &[u8]) -> Result<usize, String>;
}
pub(super) struct Device<T: ControlIo> {
    io: T,
}
impl<T: ControlIo> Device<T> {
    pub(super) fn checked(mut io: T) -> Result<Self, String> {
        let mut bytes = [0; 24];
        if io.read(DESCRIPTOR, &mut bytes)? != 24 || bytes != super::report_descriptor() {
            return Err("claimed boot USB report descriptor differs".into());
        }
        Ok(Self { io })
    }
}
fn error(message: impl Into<String>) -> TransportError {
    TransportError::new(TransportFailure::Rejected, message)
}
impl<T: ControlIo> LocalFeatureTransport for Device<T> {
    fn set_local(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() != 64 || frame[0] != 7 {
            return Err(error("boot USB accepts only a complete report 07"));
        }
        if self.io.write(SET, frame).map_err(error)? != 64 {
            return Err(error("short boot USB Feature Set"));
        }
        Ok(())
    }
    fn get_local(&mut self, id: u8, length: usize) -> Result<Vec<u8>, TransportError> {
        if id != 7 || length != 64 {
            return Err(error("boot USB Get requires report 07 and length 64"));
        }
        let mut frame = vec![0; 64];
        frame[0] = 7;
        if self.io.read(GET, &mut frame).map_err(error)? != 64 {
            return Err(error("short boot USB Feature Get"));
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};
    enum Expected {
        Read(Setup, Result<(Vec<u8>, usize), String>),
        Write(Setup, Vec<u8>, Result<usize, String>),
    }
    struct Io {
        steps: VecDeque<Expected>,
        drops: Rc<RefCell<u32>>,
    }
    impl Drop for Io {
        fn drop(&mut self) {
            *self.drops.borrow_mut() += 1;
        }
    }
    impl ControlIo for Io {
        fn read(&mut self, setup: Setup, buffer: &mut [u8]) -> Result<usize, String> {
            let Some(Expected::Read(want, result)) = self.steps.pop_front() else {
                panic!("ungranted control read");
            };
            assert_eq!(setup, want);
            let (data, n) = result?;
            assert_eq!(buffer.len(), usize::from(setup.length));
            buffer[..data.len()].copy_from_slice(&data);
            Ok(n)
        }
        fn write(&mut self, setup: Setup, buffer: &[u8]) -> Result<usize, String> {
            let Some(Expected::Write(want, data, result)) = self.steps.pop_front() else {
                panic!("ungranted control write");
            };
            assert_eq!(setup, want);
            assert_eq!(buffer, data);
            result
        }
    }
    fn io(steps: Vec<Expected>) -> (Io, Rc<RefCell<u32>>) {
        let drops = Rc::new(RefCell::new(0));
        (
            Io {
                steps: steps.into(),
                drops: drops.clone(),
            },
            drops,
        )
    }
    fn descriptor() -> Expected {
        Expected::Read(
            DESCRIPTOR,
            Ok((super::super::report_descriptor().to_vec(), 24)),
        )
    }
    #[test]
    fn only_exact_descriptor_and_feature_control_setups_are_emitted() {
        let mut frame = vec![0; 64];
        frame[..2].copy_from_slice(&[7, 2]);
        let mut reply = frame.clone();
        reply[32..].fill(0x5a);
        let (io, drops) = io(vec![
            descriptor(),
            Expected::Write(SET, frame.clone(), Ok(64)),
            Expected::Read(GET, Ok((reply.clone(), 64))),
        ]);
        let mut device = Device::checked(io).unwrap();
        device.set_local(&frame).unwrap();
        assert_eq!(device.get_local(7, 64).unwrap(), reply);
        assert!(device.io.steps.is_empty());
        drop(device);
        assert_eq!(*drops.borrow(), 1);
    }
    #[test]
    fn failed_or_false_descriptor_releases_the_claimed_io_and_sends_no_feature() {
        for result in [
            Err("read failed".into()),
            Ok((vec![0; 24], 24)),
            Ok((super::super::report_descriptor().to_vec(), 23)),
        ] {
            let (io, drops) = io(vec![Expected::Read(DESCRIPTOR, result)]);
            assert!(Device::checked(io).is_err());
            assert_eq!(*drops.borrow(), 1);
        }
    }
    #[test]
    fn malformed_report_or_length_never_reaches_usb_io() {
        let (io, _) = io(vec![descriptor()]);
        let mut device = Device::checked(io).unwrap();
        for frame in [vec![], vec![7; 63], vec![8; 64], vec![7; 65]] {
            assert!(device.set_local(&frame).is_err());
        }
        for (id, n) in [(0, 64), (8, 64), (7, 63), (7, 65)] {
            assert!(device.get_local(id, n).is_err());
        }
        assert!(device.io.steps.is_empty());
    }
    #[test]
    fn short_control_calls_and_failures_are_not_retried() {
        let frame = vec![7; 64];
        for result in [Ok(63), Err("timeout".into()), Err("disconnected".into())] {
            let (io, _) = io(vec![
                descriptor(),
                Expected::Write(SET, frame.clone(), result),
            ]);
            let mut device = Device::checked(io).unwrap();
            assert!(device.set_local(&frame).is_err());
            assert!(device.io.steps.is_empty());
        }
        let (io, _) = io(vec![
            descriptor(),
            Expected::Read(GET, Ok((vec![7; 63], 63))),
        ]);
        let mut device = Device::checked(io).unwrap();
        assert!(device.get_local(7, 64).is_err());
        assert!(device.io.steps.is_empty());
    }
}
