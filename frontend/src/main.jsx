import React from 'react'
import { createRoot } from 'react-dom/client'
// Preline UI plugins actually used (each registers itself on window): modals + offcanvas,
// accordions, tooltips and tabs. Importing per plugin keeps the bundle small.
import 'preline/plugins/overlay'
import 'preline/plugins/accordion'
import 'preline/plugins/tooltip'
import 'preline/plugins/tabs'
import App from './App.jsx'
import './styles.css'

document.documentElement.classList.add('dark')

createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
