/**
 * 核心机制：
 * 1. 链接建立（三次握手）
 * 2. 链接断开 (四次挥手)
 * 3. 传输：
 *      * 滑动窗口机制：拥塞避免、快速重传、快速恢复、流量控制、累计确认等等
 * 
 * 累计确认：
 * 接收方只确认收到的连续排列的最后一个子节，这样发送方可以确认该子节前的所有数据都已收到，比如:
 * 发送: 100-199 200-299 300 - 399, 那么接收方收到这些数据后只会ack 400, 这里假设三者连续到达
 * 
 * 如果乱序到达，如：
 * 100-199 300-399 200-299, 在seg 2到达时，因为乱序，接收方只会回复ack=200, 表示仅200以前的子节收到
 * 
 * 慢启动：
 * 1. 即逐步扩大发送窗口(cwnd)
 * 2. 初始窗口控制在1-10 MSS
 * 3. 收到一个ack, 窗口就扩大一倍 直到网络拥塞或者达到阈值(ssthresh) （同1.） 指数增长
 *
 * 慢启动并不慢，他是相对于早期TCP实现而言的
 *
 * 拥塞避免：
 * 当cwnd大小 >= sssthresh 时，进行拥塞避免:
 * 1. 每个RTT内，cwnd += MSS (约) 线性增长，这里不是每个ack增加1 MSS，需要有一个算法控制
 * 
 * 这里的RTT是指回路时间，即发送一个segment-收到一个ack 对应的时间
 * 
 * 快速重传：
 * 发送方不等待某个segment的超时的情况下，在满足特定条件立刻重传
 * 条件：
 * 连续收到3个重复的ack，并且该ack 小于要被重传的seg 子节序号
 * 这表明，每个ack都收到了发送方后续发送的数据，但是得不到对应的ack，说明中间有数据丢失时
 * 举例:
 * 1 seq=100 OK
 * 2 seq=200 丢失
 * 3 seq=300 OK
 * 4 seq=400 OK
 * 5 seq=500 OK
 * 这里send 1得到ack =200, send 2 没响应， send 3 ack=200, send 4= 200, 这里就出发了快速重传， 重传ack = 200
 * 注意这里重传不一定意味着seq=200 真的丢了，只是怀疑其大概率丢了
 * 
 * 快速恢复：
 * 出现快速重传时，不回到初始状态，只是减速
 * 1. 设置ssthresh(阈值) = cwnd / 2 (减半)
 * 2. cwnd = ssthresh + 3*MSS
 * 3. 立即重传丢失的seg
 * 4. 每收到一个重复ack, 按照拥塞避免策略线性增长cwnd
 * 5. 收到新ACK，cwnd = ssthresh, 恢复到拥塞避免状态
 * 
 * 快速恢复和快速重传时搭配使用的
 * 快速重传在重发seg后，sender依然可能会收到重复ack(seq=200). 但是我们的窗口已经减半了. 此时我们继续收到
 * ack(seq=200)的话，我们就在减半的基础上，线性增加窗口。 当新的ack(seq=600) 到达时，意味着传输状态已经恢复，我们可以
 * 在当前减半+线性增长的基础上进入拥塞避免了（5.）
 * 
 * 
 * 
 * 混淆概念：
 * TCP的RWND、CWND都是以子节为单位的，TCP是面相流的协议。虽然发送、接收都是由tcp 报文切分，但报文只是传输手段，管理并不是 以报文为单位
 * 
 * TCP的ACK响应：
 * TCP的每一个segment都可以被响应，但不一定会，处于效率考虑，某些情况下可以合并多个segment进行ack 或者主动延迟
 * 以检查应用层是否会发数据，以带有有效载荷响应。
 * 
 * 在给定时间内（定时器作用之一）没有新数据，就需要发送ack
 * 
 * 接收方的ACK：
 * 接收方的ACK是累计确认接收子节序号+1， 表示自己想要收到的子节序，这里发送方可以很容易推断
 * 
 * TCP 还有一个流量控制窗口，是为了避免接收方接收不过来而设置的，是RWND。发送方用来做拥塞避免的是CWND
 * recver 通过Tcpheader中的窗口字段告知自己的当前的可用窗口大小，以防过载。
 * recver 根据application 读取的情况持续更新RWND ==>防止自身爆炸
 * 
 * 如果RWND=0, 发送方会暂停发送（阻塞），触发0窗口探测机制
 * 
 * 实际发送方的窗口会取min(CWND, RWND)
 * 
 * RWND 通常初始化为4-64kB, 视配置，现代tcp 支持窗口缩放以支持高带宽， 可以通过 sysctl net.ipv4.tcp_rmem 查看 (min default max)
 * 
 * 零窗口探测：
 * sender 避免无限期等待.
 * 
 * 检测窗口是否已恢复，以及检测防止接收方因某种原因ACK未到达（可以想象sender 主动发送一个请求单 recver
 * 因各种原因没收到或者没给出恢复，因此只检测一次不够）
 * 
 * sender使用坚持定时器(persist timer), 定期（时间可变）发送一个小探测包()，仅用于探测recver响应，不会携带新数据
 * 如果recver 空闲，则返回新的rwnd > 0, 此时sender恢复传输
 * 如果rwnd=0, 则继续等待并调整探测间隔（像cwnd 一样指数增加，直到最大上限,一般不超过60s）
 * linux 下可以调整这个参数
 * 如果多次探测无响应（如接收方应用崩溃），则TCP会触发RTO（超时） 关闭链接
 * 
 * 
 * 
 * tcp 保活（非核心机制）
 */
use bitflags::bitflags;
use std::collections::{BTreeMap, VecDeque};
use std::{io, time};
// crate 当前模块树内可见
bitflags! {
    pub(crate) struct Available: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

#[derive(Debug)]
enum State {
    //Listen,
    SynRcvd,
    Estab,
    FinWait1,
    FinWait2,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Estab | State::FinWait1 | State::FinWait2 | State::TimeWait => true,
        }
    }
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: RecvSequenceSpace,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
    timers: Timers,

    pub(crate) incoming: VecDeque<u8>,
    /// 已发送，但尚未确认的子节数据
    /// 这里的VecDeque 应该和C++中的std::deque 一样
    pub(crate) unacked: VecDeque<u8>,

    pub(crate) closed: bool,
    closed_at: Option<u32>,
}

struct Timers {
    /// BTree => BTree 特点?
    /// key 是发送序号， value 是时间
    send_times: BTreeMap<u32, time::Instant>,
    /// 平滑往返时间，和拥塞避免有关系
    srtt: f64,
}

impl Connection {
    pub(crate) fn is_rcv_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            // TODO: any state after rcvd FIN, so also CLOSE-WAIT, LAST-ACK, CLOSED, CLOSING
            true
        } else {
            false
        }
    }

    fn availability(&self) -> Available {
        let mut a = Available::empty();
        if self.is_rcv_closed() || !self.incoming.is_empty() {
            a |= Available::READ;
        }
        // TODO: take into account self.state
        // TODO: set Available::WRITE
        a
    }
}

/**
 * 一个 TCP segment = TCP header + TCP payload,即对应用层数据的切分
 * 数据链路层 - 帧 frame
 * 网络层 - 包 packet
 * 传输层 - 段 segment
 */

/// State of the Send Sequence Space (RFC 793 S3.2 F4)
///
/// ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```
/// 这里注意，三个关键变量的单位都是子节，而不是什么段编号!
struct SendSequenceSpace {
    /// send unacknowledged
    ///  关键变量 最早未确认的**子节**
    una: u32,
    /// send next
    /// 关键变量 下一个发送的子节序号
    /// 对于syn/fin 等特殊的ack，需要额外占用一个子节，会影响到这个nxt
    /// 对于正常传输时的ack，如果回ack不携带任何数据，这个nxt 就不会增长
    nxt: u32,
    /// send window cwnd
    ///  关键变量 可发送范围，接收方告知 三者组成滑动窗口[SND.UNA, SND.UNA + SND.WND)
    /// 这里的wnd 不等同于cwnd 或者rwnd, 是两者的最小值
    wnd: u16, 
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    /// 初始**子节序号** 这里用于判定una起始条件
    iss: u32,
}

/// State of the Receive Sequence Space (RFC 793 S3.2 F5)
///
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct RecvSequenceSpace {
    /// receive next
    /// 下一个期望接收的序号
    nxt: u32,
    /// receive window => 关键变量 rwnd
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    // 站在server 角色建立一个链接
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        let buf = [0u8; 1500];
        if !tcph.syn() {
            // only expected SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut c = Connection {
            timers: Timers {
                send_times: Default::default(),
                srtt: time::Duration::from_secs(1 * 60).as_secs_f64(),
            },
            state: State::SynRcvd,
            send: SendSequenceSpace {
                iss,
                una: iss,
                nxt: iss,
                wnd: wnd,
                up: false,

                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequenceSpace {
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(), // 这里使用accept带过来的window_size() 初始化窗口, 这里表示的是有效数据吗？
                up: false,
            },
            tcp: etherparse::TcpHeader::new(tcph.destination_port(), tcph.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
                etherparse::IpTrafficClass::Tcp,
                [
                    iph.destination()[0],
                    iph.destination()[1],
                    iph.destination()[2],
                    iph.destination()[3],
                ],
                [
                    iph.source()[0],
                    iph.source()[1],
                    iph.source()[2],
                    iph.source()[3],
                ],
            ),

            incoming: Default::default(),
            unacked: Default::default(),

            closed: false,
            closed_at: None,
        };

        // need to start establishing a connection
        // 返回响应, syn=true 代表准备建立， 三次握手的第二步
        // 这里的syn=true, ack=true 都是标志位
        // 可以看到这里设置了syn的标志位
        c.tcp.syn = true;
        c.tcp.ack = true;
        // send.nxt => 下一个要发送的子节序号, limit 应该指示大小
        c.write(nic, c.send.nxt, 0)?;
        Ok(Some(c))
    }

    // 这里的seq + limit 就确认了发送的segment
    fn write(&mut self, nic: &mut tun_tap::Iface, seq: u32, mut limit: usize) -> io::Result<usize> {
        let mut buf = [0u8; 1500];
        // 这里的sequence_number 表示这一segment的第一个子节序号
        self.tcp.sequence_number = seq;
        // 确认字节序好: recver 预期的下一个子节
        self.tcp.acknowledgment_number = self.recv.nxt;

        // TODO: return +1 for SYN/FIN
        println!(
            "write(ack: {}, seq: {}, limit: {}) syn {:?} fin {:?}",
            self.recv.nxt - self.recv.irs, seq, limit, self.tcp.syn, self.tcp.fin,
        );

        let mut offset = seq.wrapping_sub(self.send.una) as usize;
        // we need to special-case the two "virtual" bytes SYN and FIN
        if let Some(closed_at) = self.closed_at {
            if seq == closed_at.wrapping_add(1) {
                // trying to write following FIN
                offset = 0;
                limit = 0;
            }
        }
        println!(
            "using offset {} base {} in {:?}",
            offset,
            self.send.una,
            self.unacked.as_slices()
        );
        // rust 中.. 语法表示范围操作符， 用于切片或者循环
        // range=0..5 => [0,5)
        // range=0..=5 => [0,5] (个人理解无必要)
        // slice: arr=[1, 2, 3,4,5] , slices =  &arr[1..4] => [2, 3, 4] 取[1,4)
        // if let Point { x, .. } = p; // 只匹配 x，忽略 y 
        // 这里的as_slices 就是把deque 中的分裂的chunk 作为slices 返回遍历
        // vecdeque 是为了解决频繁头部插入效率底下的问题， vec push front的效率比较低(可以check std::vector 是否支持push_front)
        // vecdeque 使用的连续存储的ringbuffer，在扩容时，仍然需要整个数组复制
        let (mut h, mut t) = self.unacked.as_slices();
        if h.len() >= offset {
            h = &h[offset..];
        } else {
            let skipped = h.len();
            h = &[];
            t = &t[(offset - skipped)..];
        }
        // 载荷大小
        let max_data = std::cmp::min(limit, h.len() + t.len());
        let size = std::cmp::min(
            // buf = 1 MSS
            buf.len(),
            // tcp 头部+ip 头部+总数据大小
            self.tcp.header_len() as usize + self.ip.header_len() as usize + max_data,
        );
        // 设置载荷大小， 这里要注意 ip.header_len 是否可变的？为何需要单独设置载荷大小
        self.ip
            .set_payload_len(size - self.ip.header_len() as usize);

        // write out the headers and the payload
        use std::io::Write;
        let buf_len = buf.len();
        let mut unwritten = &mut buf[..];
        // 写入buffer
        // 这里的unwrittern 指针是否自动变化 => 会，这里ip.write 是一个泛型，默认类型是io::Write
        self.ip.write(&mut unwritten);
        // ip 头部位置, 这里计算感觉也有问题， 这里 unwritten.len() == buf_len?
        let ip_header_ends_at = buf_len - unwritten.len();

        // postpone writing the tcp header because we need the payload as one contiguous slice to calculate the tcp checksum
        // 这里是不是一个bug, 应该是ip.header_len() => 不是，假设其size 缩减
        // 这里的unwritten 是用来存储payloads的
        unwritten = &mut unwritten[self.tcp.header_len() as usize..];
        // 这里tcp_header_ends 包含了iph 和tcph
        let tcp_header_ends_at = buf_len - unwritten.len();

        // write out the payload
        // 尽可能的写入未ack得数据 
        // 未ack的数据包含新数据和已发送未响应的
        let payload_bytes = {
            let mut written = 0;
            let mut limit = max_data;

            // first, write as much as we can from h
            let p1l = std::cmp::min(limit, h.len());
            written += unwritten.write(&h[..p1l])?;
            limit -= written;

            // then, write more (if we can) from t
            let p2l = std::cmp::min(limit, t.len());
            written += unwritten.write(&t[..p2l])?;
            written
        };
        // 看写了多少，有时候不一定能写完
        let payload_ends_at = buf_len - unwritten.len();

        // finally we can calculate the tcp checksum and write out the tcp header
        self.tcp.checksum = self
            .tcp
            .calc_checksum_ipv4(&self.ip, &buf[tcp_header_ends_at..payload_ends_at])
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_ends_at..tcp_header_ends_at];
        self.tcp.write(&mut tcp_header_buf);
        // 计算下一个序号
        let mut next_seq = seq.wrapping_add(payload_bytes as u32);
        // syn不携带数据，要额外的占用一个序列号
        // 这里要看syn/fin的标志是发送方设置的还是怎么（接收方回消息时也可能设置）
        // 这个实现是正确的
        if self.tcp.syn {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            next_seq = next_seq.wrapping_add(1);
            self.tcp.fin = false;
        }
        if wrapping_lt(self.send.nxt, next_seq) {
            self.send.nxt = next_seq;
        }
        // 定时器更新，key是发送的子节序号
        self.timers.send_times.insert(seq, time::Instant::now());
        // 发送，iph tcph payloads
        nic.send(&buf[..payload_ends_at])?;
        Ok(payload_bytes)
    }

    fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        // TODO: fix sequence numbers here
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // TODO: handle synchronized RST
        // 3.  If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptible acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.write(nic, self.send.nxt, 0)?;
        Ok(())
    }

    pub(crate) fn on_tick(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        // 没有任何事情可做
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shutdown our write side and the other side acked, no need to (re)transmit anything
            return Ok(());
        }

        // eprintln!("ON TICK: state {:?} una {} nxt {} unacked {:?}",
        //           self.state, self.send.una, self.send.nxt, self.unacked);

        let nunacked_data = self.closed_at.unwrap_or(self.send.nxt).wrapping_sub(self.send.una);
        let nunsent_data = self.unacked.len() as u32 - nunacked_data;
        // 这里是取una位置的时间
        let waited_for = self
            .timers
            .send_times
            .range(self.send.una..)
            .next()
            .map(|t| t.1.elapsed());

        let should_retransmit = if let Some(waited_for) = waited_for {
            // 超时，并且超过1.5 srtt
            waited_for > time::Duration::from_secs(1)
                && waited_for.as_secs_f64() > 1.5 * self.timers.srtt
        } else {
            false
        };

        if should_retransmit {
            let resend: u32 = std::cmp::min(self.unacked.len() as u32, self.send.wnd as u32);
            // 这个条件啥意思?
            // 应该反过来 self.closed() && xxx 表明在关闭的条件下，要重发数据
            // 这里的条件是buffer足够，因此直接发送Fin 来断开链接了
            // 否则还需要再来几次，不能发送fin
            if resend < self.send.wnd as u32 && self.closed {
                // can we include the FIN?
                // 发送结束
                self.tcp.fin = true;
                // 表明自己在何处结束 (self.una, self.una + self.unacked) 就是全部未响应子节
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            self.write(nic, self.send.una, resend as usize)?;
        } else {
            // we should send new data if we have new data and space in the window
            if nunsent_data == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            let allowed = self.send.wnd as u32 - nunacked_data;
            if allowed == 0 {
                return Ok(());
            }

            let send = std::cmp::min(nunsent_data, allowed);
            // 还有足够buffer发送，因此直接发
            if send < allowed && self.closed && self.closed_at.is_none() {
                self.tcp.fin = true;
                // 这里设置标志位，表明在那个位置关闭链接
                self.closed_at = Some(self.send.una.wrapping_add(self.unacked.len() as u32));
            }
            
            self.write(nic, self.send.nxt, send as usize)?;
        }

        Ok(())
    }

    // 这个传输过程不涉及c/s，只有发送方、接收方
    // Send 就是用于控制Send的部分，Recv就是用于控制Recv的部分，两者是独立的，和peer协作
    pub(crate) fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>, // 收到数据
        data: &'a [u8],
    ) -> io::Result<Available> {
        // first, check that sequence numbers are valid (RFC 793 S3.3)
        // 发送方给的字节序
        let seqn = tcph.sequence_number(); // 头部带来的子节序号
        let mut slen = data.len() as u32; // payload 数据长度
        // 是fin 字段或者syn 字段，accept 阶段已经进入了syn_rcvd 状态
        // 已经分配了链接相关的资源
        // syn/fin 要额外占用一个子节
        // 一个是slice 一个是header
        if tcph.fin() {
            
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        // recv的下一个序号 += 响应窗口长度
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        
        let okay = if slen == 0 {
            // slen == 0 => 没有负载 可能是一些探测包, 不是握手包
            // zero-length segment has separate rules for acceptance
            // 说明自己没有可接受的buffer了
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    false
                } else {
                    // 发送方给的字节序和下一个与其的字节序相等
                    true
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                // seqn not in [recv.nxt-1, wend], 超出了窗口范围， 这里的rcv wnd 的某些位置要给
                // 未到的包留着，数据要按照字节序存储到指定位置
                false
            } else {
                true
            }
        } else { // 有数据
            if self.recv.wnd == 0 { // 这里无法再接收了
                false
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend)
                && !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn.wrapping_add(slen - 1),
                    wend,
                )
            {
                // seqn in (rnxt-1, wend)
                // 接收到的seg 字节序号范围 要在窗口内
                // seqn+slen -1, in (rnxt-1,  wend)
                false
            } else {
                true
            }
        };
        // 挂了，写不了
        if !okay {
            eprintln!("NOT OKAY");
            self.write(nic, self.send.nxt, 0)?;
            return Ok(self.availability());
        }
        // Seg 是否是ack
        if !tcph.ack() {
            // 属于syn() 包
            if tcph.syn() {
                // got SYN part of initial handshake
                // 不带数据
                assert!(data.is_empty());
                // 增加recv.nxt, syn 需要带一字节
                self.recv.nxt = seqn.wrapping_add(1);
            }
            return Ok(self.availability());
        }
        // 确认序号
        let ackn = tcph.acknowledgment_number();
        // 状态处理
        if let State::SynRcvd = self.state {
            if is_between_wrapped(
                self.send.una.wrapping_sub(1),
                ackn,
                self.send.nxt.wrapping_add(1),
            ) {
                // must have ACKed our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Estab;
            } else {
                // TODO: <SEQ=SEG.ACK><CTL=RST>
            }
        }

        if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
            // 这里，send.nxt 一定位于可发送窗口内
            // 这里要求ackn 不能超过尚未发送的数据
            if is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                println!(
                    "ack for {} (last: {}); prune in {:?}",
                    ackn, self.send.una, self.unacked
                );
                // 有未确认的数据
                if !self.unacked.is_empty() {
                    // 最早未确认子节
                    // send.una 要跳过syn 占用的1子节
                    let data_start = if self.send.una == self.send.iss {
                        // send.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.una.wrapping_add(1)
                    } else {
                        self.send.una
                    };
                    // min(ackn-ds, unack.len())
                    // 这里指删去那些数据，联想累计确认， 回复ackn 时，指 ackn 之前的子节都已收到且连续
                    // 因此这里可以安全的从unack 中删去(ackn-ds) 中的数据，应该不会出现超过unacked.len的情况
                    // 不过网络上 各种情况都有，内核中的代码，可能是要做这种检查的
                    let acked_data_end = std::cmp::min(ackn.wrapping_sub(data_start) as usize, self.unacked.len());
                    // 删除这部分数据
                    self.unacked.drain(..acked_data_end);

                    let old = std::mem::replace(&mut self.timers.send_times, BTreeMap::new());

                    let una = self.send.una;
                    let mut srtt = &mut self.timers.srtt;
                    self.timers
                        .send_times
                        .extend(old.into_iter().filter_map(|(seq, sent)| {
                            // seq 在 una 和 ackn 之间
                            // 这里ackn 是对端发过来的响应包
                            if is_between_wrapped(una, seq, ackn) {
                                // 更新平滑时间，这里应该是同时把这些东西删去
                                // 指数加权平均
                                *srtt = 0.8 * *srtt + (1.0 - 0.8) * sent.elapsed().as_secs_f64();
                                None
                            } else {
                                Some((seq, sent))
                            }
                        }));
                }
                // 更新最早未回复
                self.send.una = ackn;
            }

            // TODO: if unacked empty and waiting flush, notify
            // TODO: update window
        }
        // 四次挥手处理
        // 发送fin-> 进入finwait1, 得到ack进入finwait2,  收到对端发送的fin, 则结束链接
        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.una == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed!
                    // 切换,等待对端发fin
                    self.state = State::FinWait2;
                }
            }
        }
        // 数据处理
        if !data.is_empty() {
            if let State::Estab | State::FinWait1 | State::FinWait2 = self.state {
                // rcv.nxt - seqn  这个seqn 一定不能超过rcv.nxt吗?
                // 起始阶段，recv.nxt 是一个比较小的值，这里sender如何处理?
                // 这里的seqn 是此seg的起始子节序号，因此assert recv.nxt - seqn >= 0
                // 如果 =0， 说明刚好是预期子节
                // 如果 >0, 说明有重复数据，重复了多少即是这个unread_data_at， 即[0..unread_data_at] 
                // 是已被接受且重复了的
                let mut unread_data_at = self.recv.nxt.wrapping_sub(seqn) as usize;
                // 此段全是重复数据
                if unread_data_at > data.len() {
                    // we must have received a re-transmitted FIN that we have already seen
                    // nxt points to beyond the fin, but the fin is not in data!
                    assert_eq!(unread_data_at, data.len() + 1);
                    unread_data_at = 0;
                }
                // 扩充未读数据
                self.incoming.extend(&data[unread_data_at..]);

                /*
                Once the TCP takes responsibility for the data it advances
                RCV.NXT over the data accepted, and adjusts RCV.WND as
                apporopriate to the current buffer availability.  The total of
                RCV.NXT and RCV.WND should not be reduced.
                 */
                // 增长recv.nxt
                // its'a bug. 除非这里的data_len 被slice
                self.recv.nxt = seqn.wrapping_add(data.len() as u32);

                // Send an acknowledgment of the form: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                // TODO: maybe just tick to piggyback ack on data?
                // 回复，前面非ack得情况已经回复了，这里不清楚是在干啥
                self.write(nic, self.send.nxt, 0)?;
            }
        }
        // FinWait2的状态下，收到Fin，则结束
        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection!
                    self.recv.nxt = self.recv.nxt.wrapping_add(1);
                    self.write(nic, self.send.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.availability())
    }

    pub(crate) fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        // 这里强制设置为FinWait1，但是似乎没有发送 fin
        match self.state {
            State::SynRcvd | State::Estab => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "already closing",
                ))
            }
        };
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    //     TCP determines if a data segment is "old" or "new" by testing
    //     whether its sequence number is within 2**31 bytes of the left edge
    //     of the window, and if it is not, discarding the data as "old".  To
    //     insure that new data is never mistakenly considered old and vice-
    //     versa, the left edge of the sender's window has to be at most
    //     2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}
