import React from 'react'
import 'primeicons/primeicons.css';

const StudentData = () => {
  return (
    <div className="student-data">
      <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '10px', marginBottom: '10px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 5px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <i className="pi pi-star" style={{ color: '#ffeb3b', marginRight: '10px' }} /> 
          <span style={{ fontSize: '1rem', marginLeft: '0px' }}>Aptitude Score</span> 
        </div>
        <h2 style={{ marginLeft: '25px', fontSize: '1.5rem' }}>147</h2> 
      </div>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '10px', marginBottom: '10px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 5px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <i className="pi pi-user" style={{ color: '#3f51b5', marginRight: '10px' }} /> 
          <span style={{ fontSize: '1rem', marginLeft: '0px' }}>Personality Type</span> 
        </div>
        <h2 style={{ marginLeft: '25px', fontSize: '1.5rem' }}>INTJ</h2> 
      </div>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '10px', marginBottom: '10px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 5px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <i className="pi pi-eye" style={{ color: '#4caf50', marginRight: '10px' }} /> 
          <span style={{ fontSize: '1rem', marginLeft: '0px' }}>Learning Type</span> 
        </div>
        <h2 style={{ marginLeft: '25px', fontSize: '1.5rem' }}>Visual</h2>
      </div>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '10px', marginBottom: '10px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 5px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <i className="pi pi-check-circle" style={{ color: '#ff9800', marginRight: '10px' }} /> 
          <span style={{ fontSize: '1rem', marginLeft: '0px' }}>Completion</span> 
        </div>
        <h2 style={{ marginLeft: '25px', fontSize: '1.5rem' }}>45%</h2>
      </div>
      <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-start', padding: '10px', marginBottom: '10px', backgroundColor: 'white', borderRadius: '8px', boxShadow: '0 2px 5px rgba(0,0,0,0.1)' }}>
        <div style={{ display: 'flex', alignItems: 'center' }}>
          <i className="pi pi-key" style={{ color: '#f44336', marginRight: '10px' }} /> 
          <span style={{ fontSize: '1rem', marginLeft: '0px' }}>Account Type</span> 
        </div>
        <h2 style={{ marginLeft: '25px', fontSize: '1.5rem' }}>Student</h2> 
      </div>
    </div>
  )
}

export default StudentData