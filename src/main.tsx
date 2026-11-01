import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import ChatApp from './chat/ChatApp.tsx';
import './index.css';

// The new chat-style UI is the default; the original dashboard stays available at /?classic=1.
const classic = new URLSearchParams(window.location.search).get('classic') === '1';
createRoot(document.getElementById('root')!).render(classic ? <App /> : <ChatApp />);
