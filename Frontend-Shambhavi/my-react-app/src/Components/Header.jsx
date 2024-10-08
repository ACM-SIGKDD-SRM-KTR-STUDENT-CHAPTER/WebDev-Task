import React from 'react'
import 'primeicons/primeicons.css';

const Header = () => {
  return (
    <header className="header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px' }}>
      <h3>Dashboard</h3>
      <div className="profile-section" style={{ display: 'flex', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', marginRight: '15px' }}>
          <i className="pi pi-bell" style={{ marginRight: '10px', cursor: 'pointer' }} />
          <i className="pi pi-cog" style={{ marginRight: '10px', cursor: 'pointer' }} />
        </div>
        <div className="profile-pic" style={{ width: '40px', height: '40px', borderRadius: '50%', backgroundColor: '#ccc', position: 'relative', marginRight: '10px' }}>
          <i className="pi pi-user" style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', fontSize: '20px', color: '#fff' }} />
        </div>
        <div className="profile" style={{ textAlign: 'right' }}>
          <span style={{ fontWeight: 'bold' }}>Student</span>
          <br />
          <span>Shambhavi Akhouri</span>
        </div>
      </div>
    </header>
  )
}

export default Header