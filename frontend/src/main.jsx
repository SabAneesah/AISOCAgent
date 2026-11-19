import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './styles.css';

class DashboardErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    console.error('SentinelAI dashboard render failed:', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return <main style={{ minHeight: '100vh', background: '#0b111b', color: '#e8edf4', padding: '48px', fontFamily: 'Segoe UI, sans-serif' }}>
        <h1>SentinelAI could not render the dashboard</h1>
        <p style={{ color: '#e6a486' }}>{this.state.error.message}</p>
        <p>Open the browser console for the component stack, then reload this page.</p>
        <a style={{ color: '#64cbd6' }} href="http://127.0.0.1:8000/docs">Check the backend API</a>
      </main>;
    }
    return this.props.children;
  }
}

createRoot(document.getElementById('root')).render(<React.StrictMode><DashboardErrorBoundary><App /></DashboardErrorBoundary></React.StrictMode>);
