import { useState, useEffect, useRef, useCallback } from 'react';

export const ConnectionState = {
  CONNECTED: 'CONNECTED',
  RECONNECTING: 'RECONNECTING',
  DISCONNECTED: 'DISCONNECTED'
};

export function useEventStream({ maxBufferSize = 200, enabled = true } = {}) {
  const [connectionState, setConnectionState] = useState(ConnectionState.DISCONNECTED);
  const [events, setEvents] = useState([]);
  const [currentEvent, setCurrentEvent] = useState(null);
  const [totalEventsReceived, setTotalEventsReceived] = useState(0);
  const [eventsPerSec, setEventsPerSec] = useState(0.0);
  const [isPaused, setIsPaused] = useState(false);

  const wsRef = useRef(null);
  const lastSequenceRef = useRef(0);
  const seenEventIdsRef = useRef(new Set());
  const recentTimestampsRef = useRef([]);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const isPausedRef = useRef(false);

  isPausedRef.current = isPaused;

  const calculateEPS = useCallback(() => {
    const now = performance.now();
    const cutoff = now - 2000; // 2-second window
    recentTimestampsRef.current = recentTimestampsRef.current.filter(ts => ts >= cutoff);
    const count = recentTimestampsRef.current.length;
    setEventsPerSec(Math.round((count / 2.0) * 10) / 10);
  }, []);

  const connect = useCallback(() => {
    if (!enabled) return;

    if (wsRef.current) {
      try {
        wsRef.current.close();
      } catch (e) {}
    }

    const isSecure = window.location.protocol === 'https:';
    const protocol = isSecure ? 'wss:' : 'ws:';
    const host = window.location.host || 'localhost:8000';
    const wsUrl = `${protocol}//${host}/ws/events?last_sequence=${lastSequenceRef.current}`;

    try {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnectionState(ConnectionState.CONNECTED);
        reconnectAttemptsRef.current = 0;
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current);
          reconnectTimeoutRef.current = null;
        }

        // Send sync message with last sequence seen to ensure no missed events on reconnect
        if (lastSequenceRef.current > 0) {
          try {
            ws.send(JSON.stringify({
              type: 'sync',
              last_sequence: lastSequenceRef.current
            }));
          } catch (e) {}
        }
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);

          if (payload.type === 'pong' || payload.type === 'connected') {
            return;
          }

          if (payload.type === 'event' || payload.sequence !== undefined) {
            const seq = payload.sequence;
            const eventId = payload.event_id || payload.id;

            // Strict duplicate prevention: discard if sequence <= lastSequence seen or eventId already processed
            if (seq !== undefined && seq <= lastSequenceRef.current) {
              return;
            }
            if (eventId && seenEventIdsRef.current.has(eventId)) {
              return;
            }

            // Update sequence tracker
            if (seq !== undefined) {
              lastSequenceRef.current = Math.max(lastSequenceRef.current, seq);
            }
            if (eventId) {
              seenEventIdsRef.current.add(eventId);
              // Bounded seen set
              if (seenEventIdsRef.current.size > 5000) {
                const arr = Array.from(seenEventIdsRef.current);
                seenEventIdsRef.current = new Set(arr.slice(-2500));
              }
            }

            recentTimestampsRef.current.push(performance.now());
            setTotalEventsReceived(prev => prev + 1);
            setCurrentEvent(payload);

            if (!isPausedRef.current) {
              setEvents(prev => {
                // Bounded client-side buffer: keep newest maxBufferSize items
                const next = [payload, ...prev];
                return next.length > maxBufferSize ? next.slice(0, maxBufferSize) : next;
              });
            }
          }
        } catch (err) {
          console.warn("WebSocket parse error:", err);
        }
      };

      ws.onerror = () => {
        // Will trigger onclose and attempt reconnect
      };

      ws.onclose = () => {
        setConnectionState(ConnectionState.RECONNECTING);
        wsRef.current = null;

        if (enabled) {
          // Exponential backoff reconnect: 1s, 2s, 4s, max 8s
          const attempts = reconnectAttemptsRef.current;
          const delay = Math.min(1000 * Math.pow(2, attempts), 8000);
          reconnectAttemptsRef.current += 1;

          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, delay);
        }
      };
    } catch (err) {
      setConnectionState(ConnectionState.DISCONNECTED);
    }
  }, [enabled, maxBufferSize]);

  useEffect(() => {
    connect();

    // EPS calculation timer
    const epsTimer = setInterval(calculateEPS, 1000);

    return () => {
      clearInterval(epsTimer);
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect, calculateEPS]);

  const clearEvents = useCallback(() => {
    setEvents([]);
  }, []);

  const togglePause = useCallback(() => {
    setIsPaused(prev => !prev);
  }, []);

  const reconnectNow = useCallback(() => {
    if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
    reconnectAttemptsRef.current = 0;
    connect();
  }, [connect]);

  return {
    connectionState,
    events,
    currentEvent,
    totalEventsReceived,
    eventsPerSec,
    isPaused,
    clearEvents,
    togglePause,
    reconnectNow
  };
}
