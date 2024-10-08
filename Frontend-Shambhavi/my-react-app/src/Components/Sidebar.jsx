import React from 'react'
import 'primeicons/primeicons.css';

const Sidebar = () => {
  return (
    <aside className="sidebar">
    <div className="sidebar-header">
      <h2>Counsel.ai</h2>
    </div>
    <ul className="sidebar-menu">
      <li>
        <i className="pi pi-dashboard" style={{ marginRight: '8px' }} /> Dashboard
      </li>
      <li>
        <i className="pi pi-home" style={{ marginRight: '8px' }} /> Home
      </li>
      <li>
        <i className="pi pi-file" style={{ marginRight: '8px' }} /> Resources
      </li>
      <li>
        <i className="pi pi-question-circle" style={{ marginRight: '8px' }} /> How this works
      </li>
      <li>
        <i className="pi pi-info-circle" style={{ marginRight: '8px' }} /> About
      </li>
    </ul>
    <div className="sidebar-settings">
      <i className="pi pi-cog" style={{ marginRight: '8px' }} /> 
      <span>Settings</span>
    </div>
  </aside>
  )
}

export default Sidebar